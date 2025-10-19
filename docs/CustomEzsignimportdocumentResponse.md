# CustomEzsignimportdocumentResponse

An Ezsignimportdocument

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignimportdocumentID** | **number** | The unique ID of the Ezsignimportdocument | [default to undefined]
**sEzsignimportdocumentName** | **string** | The name of the Ezsignimportdocument | [default to undefined]
**fkiEzsigntemplateglobalID** | **number** | The unique ID of the Ezsigntemplateglobal | [optional] [default to undefined]
**sEzsigntemplateglobalDescription** | **string** | The description of the Ezsigntemplate | [optional] [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [optional] [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [optional] [default to undefined]

## Example

```typescript
import { CustomEzsignimportdocumentResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignimportdocumentResponse = {
    pkiEzsignimportdocumentID,
    sEzsignimportdocumentName,
    fkiEzsigntemplateglobalID,
    sEzsigntemplateglobalDescription,
    fkiEzsignfolderID,
    sEzsignfolderDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
