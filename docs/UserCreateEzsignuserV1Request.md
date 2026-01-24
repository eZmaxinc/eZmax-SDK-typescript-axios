# UserCreateEzsignuserV1Request

Request for POST /1/module/user/createEzsignuser

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sEmailAddress** | **string** | The email address. | [default to undefined]
**sPhoneRegion** | **string** | The region of the phone number. (For a North America Number only)  The region is the \&quot;514\&quot; section in this sample phone number: (514) 990-1516 x123 | [default to undefined]
**sPhoneExchange** | **string** | The exchange of the phone number. (For a North America Number only)  The exchange is the \&quot;990\&quot; section in this sample phone number: (514) 990-1516 x123 | [default to undefined]
**sPhoneNumber** | **string** | The number of the phone number. (For a North America Number only)  The number is the \&quot;1516\&quot; section in this sample phone number: (514) 990-1516 x123 | [default to undefined]
**sPhoneExtension** | **string** | The extension of the phone number.  The extension is the \&quot;123\&quot; section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers | [optional] [default to undefined]

## Example

```typescript
import { UserCreateEzsignuserV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserCreateEzsignuserV1Request = {
    fkiLanguageID,
    sUserFirstname,
    sUserLastname,
    sEmailAddress,
    sPhoneRegion,
    sPhoneExchange,
    sPhoneNumber,
    sPhoneExtension,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
