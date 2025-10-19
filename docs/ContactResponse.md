# ContactResponse

A Contact Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiContactID** | **number** | The unique ID of the Contact | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiContacttitleID** | **number** | The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)| | [default to undefined]
**fkiContactinformationsID** | **number** | The unique ID of the Contactinformations | [default to undefined]
**dtContactBirthdate** | **string** | The Birth Date of the contact | [optional] [default to undefined]
**eContactType** | [**FieldEContactType**](FieldEContactType.md) |  | [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [default to undefined]
**sContactCompany** | **string** | The Company name of the contact | [optional] [default to undefined]
**sContactOccupation** | **string** | The occupation of the Contact | [optional] [default to undefined]
**tContactNote** | **string** | The note of the Contact | [optional] [default to undefined]
**bContactIsactive** | **boolean** | Whether the contact is active or not | [default to undefined]
**objContactinformations** | [**ContactinformationsResponseCompound**](ContactinformationsResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { ContactResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ContactResponse = {
    pkiContactID,
    fkiLanguageID,
    fkiContacttitleID,
    fkiContactinformationsID,
    dtContactBirthdate,
    eContactType,
    sContactFirstname,
    sContactLastname,
    sContactCompany,
    sContactOccupation,
    tContactNote,
    bContactIsactive,
    objContactinformations,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
