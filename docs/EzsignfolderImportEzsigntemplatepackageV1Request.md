# EzsignfolderImportEzsigntemplatepackageV1Request

Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [default to undefined]
**dtEzsigndocumentDuedate** | **string** | The maximum date and time at which the Ezsigndocument can be signed. | [default to undefined]
**a_objImportEzsigntemplatepackageRelation** | [**Array&lt;CustomImportEzsigntemplatepackageRelationRequest&gt;**](CustomImportEzsigntemplatepackageRelationRequest.md) |  | [default to undefined]

## Example

```typescript
import { EzsignfolderImportEzsigntemplatepackageV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfolderImportEzsigntemplatepackageV1Request = {
    fkiEzsigntemplatepackageID,
    dtEzsigndocumentDuedate,
    a_objImportEzsigntemplatepackageRelation,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
