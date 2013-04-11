module Yesod.Auth.DeskCom.Data where

import Yesod.Core

-- | Data type for @yesod-auth-deskCom@\'s subsite.
data DeskCom = DeskCom

mkYesodSubData "DeskCom" [parseRoutes|
  /  DeskComLoginR GET
  /m DeskComMaybeLoginR GET
|]
