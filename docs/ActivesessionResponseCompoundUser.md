# ActivesessionResponseCompoundUser

An Activesession->User Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiTimezoneID** | **number** | The unique ID of the Timezone | [default to undefined]
**sAvatarUrl** | **string** | The url of the picture used as avatar | [optional] [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**bUserAddmeinezsignfolder** | **boolean** | Whether if I want to automatically add myself during the creation of Ezsignfolder of which I am the owner | [default to undefined]
**eUserEzsignsendreminderfrequency** | [**FieldEUserEzsignsendreminderfrequency**](FieldEUserEzsignsendreminderfrequency.md) |  | [default to undefined]
**iUserInterfacecolor** | **number** | The int32 representation of the interface color. For example, RGB color #39435B would be 3752795 | [default to undefined]
**bUserInterfacedark** | **boolean** | Whether to use a dark mode interface | [default to undefined]
**iUserListresult** | **number** | The number of rows to return by default in lists | [default to undefined]
**iUserFrontendgoal** | **number** | Goals save as bit wise (one bit per goal) | [default to undefined]

## Example

```typescript
import { ActivesessionResponseCompoundUser } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ActivesessionResponseCompoundUser = {
    pkiUserID,
    fkiTimezoneID,
    sAvatarUrl,
    sUserFirstname,
    sUserLastname,
    sEmailAddress,
    bUserAddmeinezsignfolder,
    eUserEzsignsendreminderfrequency,
    iUserInterfacecolor,
    bUserInterfacedark,
    iUserListresult,
    iUserFrontendgoal,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
