# EzsignbulksenddocumentmappingResponseCompound

A Ezsignbulksenddocumentmapping Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksenddocumentmappingID** | **number** | The unique ID of the Ezsignbulksenddocumentmapping. | [default to undefined]
**fkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [default to undefined]
**fkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [optional] [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [optional] [default to undefined]
**iEzsignbulksenddocumentmappingOrder** | **number** | The order in which the Ezsigntemplate or Ezsigntemplatepackage will be presented to the signatory in the Ezsignfolder. | [default to undefined]
**objEzsigntemplate** | [**EzsigntemplateResponseCompound**](EzsigntemplateResponseCompound.md) |  | [optional] [default to undefined]
**objEzsigntemplatepackage** | [**EzsigntemplatepackageResponseCompound**](EzsigntemplatepackageResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignbulksenddocumentmappingResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksenddocumentmappingResponseCompound = {
    pkiEzsignbulksenddocumentmappingID,
    fkiEzsignbulksendID,
    fkiEzsigntemplatepackageID,
    fkiEzsigntemplateID,
    iEzsignbulksenddocumentmappingOrder,
    objEzsigntemplate,
    objEzsigntemplatepackage,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
