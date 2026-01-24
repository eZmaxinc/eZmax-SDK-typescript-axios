# ContactRequestCompound

A Contact Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiContacttitleID** | **number** | The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)| | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [default to undefined]
**sContactCompany** | **string** | The Company name of the contact | [default to undefined]
**dtContactBirthdate** | **string** | The Birth Date of the contact | [optional] [default to undefined]
**objContactinformations** | [**ContactinformationsRequestCompound**](ContactinformationsRequestCompound.md) |  | [default to undefined]

## Example

```typescript
import { ContactRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ContactRequestCompound = {
    fkiContacttitleID,
    fkiLanguageID,
    sContactFirstname,
    sContactLastname,
    sContactCompany,
    dtContactBirthdate,
    objContactinformations,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
