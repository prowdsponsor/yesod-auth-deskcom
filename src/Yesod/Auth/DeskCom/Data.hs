module Yesod.Auth.DeskCom.Data where

import Control.Applicative ((<$>))
import Yesod.Core
import qualified Crypto.Random.AESCtr as CPRNG
import qualified Data.IORef as I

-- | Data type for @yesod-auth-deskCom@\'s subsite.
data DeskCom = DeskCom { deskComCprngVar :: I.IORef CPRNG.AESRNG }


-- | Initialize the 'DeskCom' subsite with a fresh CPRNG.
initDeskCom :: IO DeskCom
initDeskCom = DeskCom <$> (I.newIORef =<< CPRNG.makeSystem)


mkYesodSubData "DeskCom" [parseRoutes|
  /  DeskComLoginR GET
  /m DeskComMaybeLoginR GET
|]
