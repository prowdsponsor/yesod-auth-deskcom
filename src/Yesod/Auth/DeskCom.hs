{-# OPTIONS_GHC -fno-warn-orphans #-}
module Yesod.Auth.DeskCom
    ( YesodDeskCom(..)
    , deskComCreateCreds
    , DeskComCredentials
    , DeskComUser(..)
    , DeskComUserId(..)
    , DeskComCustomField
    , DeskCom
    , getDeskCom
    , deskComLoginRoute
    , deskComMaybeLoginRoute
    ) where

import Control.Applicative ((<$>))
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Default (Default(..))
import Data.Monoid ((<>))
import Data.Text (Text)
import Language.Haskell.TH.Syntax (Pred(ClassP), Type(VarT), mkName)
import Network.HTTP.Types (renderSimpleQuery)
import Yesod.Auth
import Yesod.Core
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Classes as Crypto
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.HMAC as HMAC
import qualified Crypto.Padding as Padding
import qualified Data.Aeson as A
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Time as TI
import Yesod.Auth.DeskCom.Data
import Database.Persist (Key)

-- | Type class that you need to implement in order to support
-- Desk.com remote authentication.
--
-- /Minimal complete definition:/ everything except for 'deskComTokenTimeout'.
class YesodAuthPersist master => YesodDeskCom master where
  -- | The credentials needed to use Multipass.  Use
  -- 'deskComCreateCreds'.  We recommend caching the resulting
  -- 'DeskComCredentials' value on your foundation data type
  -- since creating it is an expensive operation.
  deskComCredentials :: master -> DeskComCredentials

  -- | Gather information that should be given to Desk.com about
  -- an user.  Please see 'DeskComUser' for more information
  -- about what these fields mean.
  --
  -- Simple example:
  --
  -- @
  -- deskComUserInfo uid = do
  --   user <- runDB $ get uid
  --   return 'def' { 'duName'  = userName user
  --              , 'duEmail' = userEmail user }
  -- @
  --
  -- Advanced example:
  --
  -- @
  -- deskComUserInfo uid = do
  --   render <- 'getUrlRender'
  --   runDB $ do
  --     Just user <- get uid
  --     Just org  <- get (userOrganization user)
  --     return 'def' { 'duName'           = userName user
  --                , 'duEmail'          = userEmail user
  --                , 'duOrganization'   = Just (organizationName org)
  --                , 'duRemotePhotoURL' = Just (render $ UserPhotoR uid)
  --                }
  -- @
  --
  -- /Note:/ although I don't recomend this and I don't see any
  -- reason why you would do it, it /is/ possible to use
  -- 'maybeAuth' instead of 'requireAuth' and login on Desk.com
  -- with some sort of guest user should the user not be logged
  -- in.
  deskComUserInfo :: AuthId master -> HandlerT master IO DeskComUser

  -- | Each time we login an user on Desk.com, we create a token.
  -- This function defines how much time the token should be
  -- valid before expiring.  Should be greater than 0.  Defaults
  -- to 5 minutes.
  deskComTokenTimeout :: master -> TI.NominalDiffTime
  deskComTokenTimeout _ = 300 -- seconds

instance YesodDeskCom master => YesodSubDispatch DeskCom (HandlerT master IO) where
    yesodSubDispatch = $(mkYesodSubDispatch resourcesDeskCom)

-- | Create the credentials data type used by this library.  This
-- function is relatively expensive (uses SHA1 and AES), so
-- you'll probably want to cache its result.
deskComCreateCreds ::
     T.Text -- ^ The name of your site (e.g., @\"foo\"@ if your
            -- site is at @http://foo.desk.com/@).
  -> T.Text -- ^ The domain of your site
            -- (e.g. @\"foo.desk.com\"@).
  -> T.Text -- ^ The Multipass API key, a shared secret between
            -- Desk.com and your site.
  -> DeskComCredentials
deskComCreateCreds site domain apiKey = DeskComCredentials site domain aesKey hmacKey
  where
    -- Yes, I know, Desk.com's crypto is messy.
    aesKey  = AES.initKey . B.take 16 . SHA1.hash . TE.encodeUtf8 $ apiKey <> site
    hmacKey = HMAC.MacKey $ TE.encodeUtf8 apiKey


-- | Credentials used to access your Desk.com's Multipass.
data DeskComCredentials =
  DeskComCredentials
    { dccSite    :: !T.Text
    , dccDomain  :: !T.Text
    , dccAesKey  :: !AES.Key
    , dccHmacKey :: !(HMAC.MacKey SHA1.Ctx SHA1.SHA1)
    }


-- | Information about a user that is given to 'DeskCom'.  Please
-- see Desk.com's documentation
-- (<http://dev.desk.com/docs/portal/multipass>) in order to see
-- more details of how theses fields are interpreted.
--
-- Only 'duName' and 'duEmail' are required.  We suggest using
-- 'def'.
data DeskComUser =
  DeskComUser
    { duName :: Text
    -- ^ User name, at least two characters. (required)
    , duEmail :: Text
    -- ^ E-mail address. (required)
    , duUserId :: DeskComUserId
    -- ^ Desk.com expects an string to be used as the ID of the
    -- user on their system.  Defaults to 'UseYesodAuthId'.
    , duCustomFields :: [DeskComCustomField]
    -- ^ Custom fields to be set.
    , duRedirectTo :: Maybe Text
    -- ^ When @Just url@, forces the user to be redirected to
    -- @url@ after being logged in.  Otherwise, the user is
    -- redirected either to the page they were trying to view (if
    -- any) or to your portal page at Desk.com.
    } deriving (Eq, Ord, Show, Read)

-- | Fields 'duName' and 'duEmail' are required, so 'def' will be
-- 'undefined' for them.
instance Default DeskComUser where
  def = DeskComUser
          { duName         = req "duName"
          , duEmail        = req "duEmail"
          , duUserId       = def
          , duCustomFields = []
          , duRedirectTo   = Nothing
          }
    where req fi = error $ "DeskComUser's " ++ fi ++ " is a required field."


-- | Which external ID should be given to Desk.com.
data DeskComUserId =
    UseYesodAuthId
    -- ^ Use the user ID from @persistent@\'s database.  This is
    -- the recommended and default value.
  | Explicit Text
    -- ^ Use this given value.
    deriving (Eq, Ord, Show, Read)

-- | Default is 'UseYesodAuthId'.
instance Default DeskComUserId where
  def = UseYesodAuthId


-- | The value of a custom customer field as @(key, value)@.
-- Note that you have prefix your @key@ with @\"custom_\"@.
type DeskComCustomField = (Text, Text)


----------------------------------------------------------------------


-- | Create a new 'DeskCom', use this on your @config/routes@ file.
getDeskCom :: a -> DeskCom
getDeskCom = const DeskCom


-- | Redirect the user to Desk.com such that they're already
-- logged in when they arrive.  For example, you may use
-- @deskComLoginRoute@ as the login URL on Multipass config.
deskComLoginRoute :: Route DeskCom
deskComLoginRoute = DeskComLoginR


-- | If the user is logged in, redirect them to Desk.com such
-- that they're already logged in when they arrive (same as
-- 'deskComLoginRoute').  Otherwise, redirect them to Desk.com
-- without asking for credentials. For example, you may use
-- @deskComMaybeLoginRoute@ when the user clicks on a \"Support\"
-- item on a menu.
deskComMaybeLoginRoute :: Route DeskCom
deskComMaybeLoginRoute = DeskComMaybeLoginR

-- | Route used by the Desk.com remote authentication.  Works
-- both when Desk.com call us and when we call them.  Forces user
-- to be logged in.
getDeskComLoginR :: YesodDeskCom master
                 => HandlerT DeskCom (HandlerT master IO) ()
getDeskComLoginR = lift $ requireAuthId >>= redirectToMultipass


-- | Same as 'getDeskComLoginR' if the user is logged in,
-- otherwise redirect to the Desk.com portal without asking for
-- credentials.
getDeskComMaybeLoginR :: YesodDeskCom master
                      => HandlerT DeskCom (HandlerT master IO) ()
getDeskComMaybeLoginR = lift
                      $ maybeAuthId >>= maybe redirectToPortal redirectToMultipass


-- | Redirect the user to the main Desk.com portal.
redirectToPortal :: YesodDeskCom master => HandlerT master IO ()
redirectToPortal = do
  y <- getYesod
  let DeskComCredentials {..} = deskComCredentials y
  redirect $ T.concat [ "http://", dccDomain, "/" ]


-- | Redirect the user to the multipass login.
redirectToMultipass :: YesodDeskCom master
                    => AuthId master
                    -> HandlerT master IO ()
redirectToMultipass uid = do
  -- Get generic info.
  y <- getYesod
  let DeskComCredentials {..} = deskComCredentials y

  -- Get the expires timestamp.
  expires <- TI.addUTCTime (deskComTokenTimeout y) <$> liftIO TI.getCurrentTime

  -- Get information about the currently logged user.
  DeskComUser {..} <- deskComUserInfo uid
  userId <- case duUserId of
              UseYesodAuthId -> toPathPiece <$> requireAuthId
              Explicit x     -> return x

  -- Create Multipass token.
  let toStrict = B.concat . BL.toChunks
      deskComEncode
        = fst . B.spanEnd (== 61)           -- remove trailing '=' per Desk.com
        . B64URL.encode                     -- base64url encoding
      encrypt
        = deskComEncode                     -- encode as modified base64url
        . AES.encryptCBC dccAesKey blankIV  -- encrypt with AES128-CBC
        . Padding.padPKCS5 16               -- PKCS#5 padding
        . toStrict . A.encode . A.object    -- encode as JSON
      sign
        = B64.encode . Crypto.encode        -- encode as normal base64 (why??? =[)
        . HMAC.hmac' dccHmacKey             -- sign using HMAC-SHA1
      multipass = encrypt $
                    "uid"            A..= userId  :
                    "expires"        A..= expires :
                    "customer_email" A..= duEmail :
                    "customer_name"  A..= duName  :
                    [ "to" A..= to | Just to <- return duRedirectTo ] ++
                    [ ("customer_" <> k) A..= v | (k, v) <- duCustomFields ]
      signature = sign multipass
      query = [("multipass", multipass), ("signature", signature)]

  -- Redirect to Desk.com
  redirect $ T.concat [ "http://"
                      , dccDomain
                      , "/customer/authentication/multipass/callback?"
                      , TE.decodeUtf8 (renderSimpleQuery False query)
                      ]


-- | A blank IV consisting of NUL bytes.  Yes, Desk.com's messy
-- crypto avoids using IVs!
blankIV :: AES.IV
blankIV = AES.IV (B.replicate 16 0)
