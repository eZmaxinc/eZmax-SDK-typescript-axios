# EzsignsignerResponseCompoundContact

A Ezsignsigner->Contact Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiContactID** | **number** | The unique ID of the Contact | [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]
**sPhoneExtension** | **string** | The extension of the phone number.  The extension is the \&quot;123\&quot; section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers | [optional] [default to undefined]
**sPhoneE164Cell** | **string** | A phone number in E.164 Format | [optional] [default to undefined]

## Example

```typescript
import { EzsignsignerResponseCompoundContact } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignerResponseCompoundContact = {
    pkiContactID,
    sContactFirstname,
    sContactLastname,
    fkiLanguageID,
    sEmailAddress,
    sPhoneE164,
    sPhoneExtension,
    sPhoneE164Cell,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
