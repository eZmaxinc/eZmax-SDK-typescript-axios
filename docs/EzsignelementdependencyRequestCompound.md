# EzsignelementdependencyRequestCompound

An Ezsignelementdependency Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignelementdependencyID** | **number** | The unique ID of the Ezsignelementdependency | [optional] [default to undefined]
**fkiEzsignformfieldIDValidation** | **number** | The unique ID of the Ezsignformfield | [optional] [default to undefined]
**fkiEzsignformfieldgroupIDValidation** | **number** | The unique ID of the Ezsignformfieldgroup | [optional] [default to undefined]
**sEzsignelementdependencyEzsignformfieldgrouplabel** | **string** | The Label for the Ezsignformfieldgroup | [optional] [default to undefined]
**sEzsignelementdependencyEzsignformfieldlabel** | **string** | The Label for the Ezsignformfield | [optional] [default to undefined]
**eEzsignelementdependencyValidation** | [**FieldEEzsignelementdependencyValidation**](FieldEEzsignelementdependencyValidation.md) |  | [default to undefined]
**bEzsignelementdependencySelected** | **boolean** | Whether if it\&#39;s selected or not when using eEzsignelementdependencyValidation &#x3D; Selected | [optional] [default to undefined]
**eEzsignelementdependencyOperator** | [**FieldEEzsignelementdependencyOperator**](FieldEEzsignelementdependencyOperator.md) |  | [optional] [default to undefined]
**sEzsignelementdependencyValue** | **string** | The value of the Ezsignelementdependency | [optional] [default to undefined]

## Example

```typescript
import { EzsignelementdependencyRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignelementdependencyRequestCompound = {
    pkiEzsignelementdependencyID,
    fkiEzsignformfieldIDValidation,
    fkiEzsignformfieldgroupIDValidation,
    sEzsignelementdependencyEzsignformfieldgrouplabel,
    sEzsignelementdependencyEzsignformfieldlabel,
    eEzsignelementdependencyValidation,
    bEzsignelementdependencySelected,
    eEzsignelementdependencyOperator,
    sEzsignelementdependencyValue,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
