module Yesod.Auth.DeskCom
    ( YesodDeskCom(..)
    , DeskComUser(..)
    , DeskComExternalId(..)
    , DeskCom
    , getDeskCom
    , deskComLoginRoute
    ) where

import Control.Applicative ((<$>))
import Control.Monad (join)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Default (Default(..))
import Data.List (intersperse)
import Data.Text (Text)
import Data.Time (getCurrentTime, formatTime)
import Language.Haskell.TH.Syntax (Pred(ClassP), Type(VarT), mkName)
import Yesod.Auth
import Yesod.Core
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as Base16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Network.HTTP.Types as H
import qualified Network.Wai as W


-- | Type class that you need to implement in order to support
-- Desk.com remote authentication.
--
-- /Minimal complete definition:/ all functions are required.
class YesodAuth master => YesodDeskCom master where
  -- | Shared secret between Desk.com and your site.
  deskComToken :: master -> B.ByteString

  -- | URL on your Desk.com's site where users should be
  -- redirected to when logging in.
  deskComAuthURL :: master -> Text

  -- | Gather information that should be given to Desk.com about
  -- an user.  Please see 'DeskComUser' for more information
  -- about what these fields mean.
  --
  -- Simple example:
  --
  -- @
  -- deskComUserInfo = do
  --   Entity uid user <- 'requireAuth'
  --   return 'def' { 'zuName'  = userName user
  --              , 'zuEmail' = userEmail user }
  -- @
  --
  -- Advanced example:
  --
  -- @
  -- deskComUserInfo = do
  --   uid <- 'requireAuthId'
  --   render <- 'getUrlRender'
  --   runDB $ do
  --     Just user <- get uid
  --     Just org  <- get (userOrganization user)
  --     return 'def' { 'zuName'           = userName user
  --                , 'zuEmail'          = userEmail user
  --                , 'zuOrganization'   = Just (organizationName org)
  --                , 'zuRemotePhotoURL' = Just (render $ UserPhotoR uid)
  --                }
  -- @
  --
  -- /Note:/ although I don't recomend this and I don't see any
  -- reason why you would do it, it /is/ possible to use
  -- 'maybeAuth' instead of 'requireAuth' and login on Desk.com
  -- with some sort of guest user should the user not be logged
  -- in.
  deskComUserInfo :: GHandler DeskCom master DeskComUser


-- | Information about a user that is given to 'DeskCom'.  Please
-- see Desk.com's documentation
-- (<http://www.zendesk.com/support/api/remote-authentication>)
-- in order to see more details of how theses fields are
-- interpreted.
--
-- Only 'zuName' and 'zuEmail' are required.
data DeskComUser =
  DeskComUser
    { zuName :: Text
    -- ^ User name, at least two characters. (required)
    , zuEmail :: Text
    -- ^ E-mail address. (required)
    , zuExternalId :: DeskComExternalId
    -- ^ An external (to Desk.com) ID that identifies this user.
    -- Defaults to 'UseYesodAuthId'.
    , zuOrganization :: Maybe Text
    -- ^ Organization the user belongs to.
    , zuTags :: [Text]
    -- ^ List of tags.
    , zuRemotePhotoURL :: Maybe Text
    -- ^ Public URL with the user's profile picture.
    } deriving (Eq, Ord, Show, Read)

-- | Fields 'zuName' and 'zuEmail' are required, so 'def' will be
-- 'undefined' for them.
instance Default DeskComUser where
  def = DeskComUser
          { zuName  = error "DeskComUser's zuName is a required field."
          , zuEmail = error "DeskComUser's zuEmail is a required field."
          , zuExternalId     = def
          , zuOrganization   = Nothing
          , zuTags           = []
          , zuRemotePhotoURL = Nothing
          }


-- | Which external ID should be given to Desk.com.
data DeskComExternalId =
    UseYesodAuthId
    -- ^ Use the user ID from @persistent@\'s database.  This is
    -- the recommended and default value.
  | Explicit Text
    -- ^ Use this given value.
  | NoExternalId
    -- ^ Do not give an external ID.
    deriving (Eq, Ord, Show, Read)

-- | Default is 'UseYesodAuthId'.
instance Default DeskComExternalId where
  def = UseYesodAuthId


----------------------------------------------------------------------


-- | Data type for @yesod-auth-deskCom@\'s subsite.
data DeskCom = DeskCom


-- | Create a new 'DeskCom', use this on your @config/routes@ file.
getDeskCom :: a -> DeskCom
getDeskCom = const DeskCom


mkYesodSub "DeskCom"
  [ClassP ''YesodDeskCom [VarT $ mkName "master"]]
  [parseRoutes|
  / DeskComLoginR GET
|]


-- | Redirect the user to Desk.com such that they're already
-- logged in when they arrive.  For example, you may use
-- @deskComLoginRoute@ when the user clicks on a \"Support\" item
-- on a menu.
deskComLoginRoute :: Route DeskCom
deskComLoginRoute = DeskComLoginR


-- | Route used by the Desk.com remote authentication.  Works both
-- when Desk.com call us and when we call them.
getDeskComLoginR :: YesodDeskCom master => GHandler DeskCom master ()
getDeskComLoginR = do
  -- Get the timestamp and the request params.
  (timestamp, getParams) <- do
    rawReqParams <- W.queryString <$> waiRequest
    case join $ lookup "timestamp" rawReqParams of
      Nothing -> do
        -- Doesn't seem to be a request from Desk.com, create our
        -- own timestamp.
        now <- liftIO getCurrentTime
        let timestamp = B8.pack $ formatTime locale "%s" now
            locale = error "yesod-auth-deskcom: never here (locale not needed)"
        return (timestamp, [("timestamp", Just timestamp)])
      Just timestamp ->
        -- Seems to be a request from Desk.com.
        --
        -- They ask us to reply to them with all the request
        -- parameters they gave us, and at first it seems that
        -- this could create a security problem: we can't confirm
        -- that the request really came from Desk.com, and a
        -- malicious person could include a parameter such as
        -- "email=foo@bar.com".  These attacks would foiled by
        -- the hash, however.
        return (timestamp, rawReqParams)

  -- Get information about the currently logged user.
  DeskComUser {..} <- deskComUserInfo
  externalId <- case zuExternalId of
                  UseYesodAuthId -> Just . toPathPiece <$> requireAuthId
                  Explicit x     -> return (Just x)
                  NoExternalId   -> return Nothing
  let tags = T.concat $ intersperse "," zuTags

  -- Calculate hash
  y <- getYesod
  let hash =
        let toBeHashed = B.concat .  cons zuName
                                  .  cons zuEmail
                                  . mcons externalId
                                  . mcons zuOrganization
                                  .  cons tags
                                  . mcons zuRemotePhotoURL
                                  .  (:)  (deskComToken y)
                                  .  (:)  timestamp
                                  $[]
            cons  = (:) . TE.encodeUtf8
            mcons = maybe id cons
        in Base16.encode $ MD5.hash toBeHashed

  -- Encode information into parameters
  let addParams = paramT  "name"             (Just zuName)
                . paramT  "email"            (Just zuEmail)
                . paramBS "hash"             (Just hash)
                . paramT  "external_id"      externalId
                . paramT  "organization"     zuOrganization
                . paramT  "tags"             (Just tags)
                . paramT  "remote_photo_url" zuRemotePhotoURL
        where
          paramT name = paramBS name . fmap TE.encodeUtf8
          paramBS name (Just t) | not (B.null t) = (:) (name, Just t)
          paramBS _    _                         = id
      params = H.renderQuery True {- add question mark -} $
               addParams getParams

  -- Redirect to Desk.com
  redirect $ deskComAuthURL y `T.append` TE.decodeUtf8 params
