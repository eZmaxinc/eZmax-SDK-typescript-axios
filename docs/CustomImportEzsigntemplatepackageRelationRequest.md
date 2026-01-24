# CustomImportEzsigntemplatepackageRelationRequest

The object used in /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage Request

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsigntemplatepackagesignerID** | **number** | The unique ID of the Ezsigntemplatepackagesigner | [optional] [default to undefined]
**fkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [default to undefined]
**sEzsigntemplatepackagesignerDescription** | **string** | The description of the Ezsigntemplatepackagesigner | [optional] [default to undefined]

## Example

```typescript
import { CustomImportEzsigntemplatepackageRelationRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomImportEzsigntemplatepackageRelationRequest = {
    fkiEzsigntemplatepackagesignerID,
    fkiEzsignfoldersignerassociationID,
    sEzsigntemplatepackagesignerDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
