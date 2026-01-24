# EzsigntemplateelementdependencyRequest

An Ezsigntemplateelementdependency Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateelementdependencyID** | **number** | The unique ID of the Ezsigntemplateelementdependency | [optional] [default to undefined]
**fkiEzsigntemplateformfieldIDValidation** | **number** | The unique ID of the Ezsigntemplateformfield | [optional] [default to undefined]
**fkiEzsigntemplateformfieldgroupIDValidation** | **number** | The unique ID of the Ezsigntemplateformfieldgroup | [optional] [default to undefined]
**sEzsigntemplateelementdependencyEzsigntemplateformfieldgrouplabel** | **string** | The Label for the Ezsigntemplateformfieldgroup | [optional] [default to undefined]
**sEzsigntemplateelementdependencyEzsigntemplateformfieldlabel** | **string** | The Label for the Ezsigntemplateformfield | [optional] [default to undefined]
**eEzsigntemplateelementdependencyValidation** | [**FieldEEzsigntemplateelementdependencyValidation**](FieldEEzsigntemplateelementdependencyValidation.md) |  | [default to undefined]
**bEzsigntemplateelementdependencySelected** | **boolean** | Whether if it\&#39;s selected or not when using eEzsigntemplateelementdependencyValidation &#x3D; Selected | [optional] [default to undefined]
**eEzsigntemplateelementdependencyOperator** | [**FieldEEzsigntemplateelementdependencyOperator**](FieldEEzsigntemplateelementdependencyOperator.md) |  | [optional] [default to undefined]
**sEzsigntemplateelementdependencyValue** | **string** | The value of the Ezsignelementdependency | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplateelementdependencyRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateelementdependencyRequest = {
    pkiEzsigntemplateelementdependencyID,
    fkiEzsigntemplateformfieldIDValidation,
    fkiEzsigntemplateformfieldgroupIDValidation,
    sEzsigntemplateelementdependencyEzsigntemplateformfieldgrouplabel,
    sEzsigntemplateelementdependencyEzsigntemplateformfieldlabel,
    eEzsigntemplateelementdependencyValidation,
    bEzsigntemplateelementdependencySelected,
    eEzsigntemplateelementdependencyOperator,
    sEzsigntemplateelementdependencyValue,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
