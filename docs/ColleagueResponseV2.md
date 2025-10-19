# ColleagueResponseV2

A Colleague Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiColleagueID** | **number** | The unique ID of the Colleague | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiUserIDColleague** | **number** | The unique ID of the User | [default to undefined]
**bColleagueEzsignemail** | **boolean** | Whether the email can be used by the cloning user in Ezsign | [default to undefined]
**bColleagueFinancial** | **boolean** | Whether the cloning user has access to the financial | [default to undefined]
**bColleagueUsecloneemail** | **boolean** | Whether the cloning user has access to the cloned user email to send communications | [default to undefined]
**bColleagueAttachment** | **boolean** | Whether the cloning user has access to the attachment | [default to undefined]
**bColleagueCanafe** | **boolean** | Whether the cloning user has access to canafe | [default to undefined]
**bColleaguePermission** | **boolean** | Whether the cloning user copies the permission of the cloned user | [default to undefined]
**bColleagueRealestatecompleted** | **boolean** | Whether if the cloning user has access to the completed folders in real estate | [default to undefined]
**dtColleagueFrom** | **string** | The from of the Colleague | [optional] [default to undefined]
**dtColleagueTo** | **string** | The to of the Colleague | [optional] [default to undefined]
**eColleagueEzsign** | [**FieldEColleagueEzsign**](FieldEColleagueEzsign.md) |  | [default to undefined]
**eColleagueRealestateinprogress** | [**FieldEColleagueRealestateinprogess**](FieldEColleagueRealestateinprogess.md) |  | [default to undefined]
**objUserName** | [**CustomUserNameResponse**](CustomUserNameResponse.md) |  | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { ColleagueResponseV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ColleagueResponseV2 = {
    pkiColleagueID,
    fkiUserID,
    fkiUserIDColleague,
    bColleagueEzsignemail,
    bColleagueFinancial,
    bColleagueUsecloneemail,
    bColleagueAttachment,
    bColleagueCanafe,
    bColleaguePermission,
    bColleagueRealestatecompleted,
    dtColleagueFrom,
    dtColleagueTo,
    eColleagueEzsign,
    eColleagueRealestateinprogress,
    objUserName,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
