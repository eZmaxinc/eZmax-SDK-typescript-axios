# EzsignimportfolderListElement

A Ezsignimportfolder List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignimportfolderID** | **number** | The unique ID of the Ezsignimportfolder | [default to undefined]
**sEzsignimportfolderName** | **string** | The name of the Ezsignimportfolder | [default to undefined]
**dtCreatedDate** | **string** | The date and time at which the object was created | [optional] [default to undefined]
**dtModifiedDate** | **string** | The date and time at which the object was last modified | [optional] [default to undefined]
**iTotalEzsignimportdocument** | **number** | The count of Ezsignimportdocument. | [optional] [default to undefined]
**iTotalEzsignimportdocumentNotImported** | **number** | The count of Ezsignimportdocument not imported in an Ezsignfolder. | [optional] [default to undefined]
**eEzsignimportfolderStatus** | [**ComputedEEzsignimportfolderStatus**](ComputedEEzsignimportfolderStatus.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignimportfolderListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignimportfolderListElement = {
    pkiEzsignimportfolderID,
    sEzsignimportfolderName,
    dtCreatedDate,
    dtModifiedDate,
    iTotalEzsignimportdocument,
    iTotalEzsignimportdocumentNotImported,
    eEzsignimportfolderStatus,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
