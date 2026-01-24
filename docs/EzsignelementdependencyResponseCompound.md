# EzsignelementdependencyResponseCompound

An Ezsignelementdependency Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignelementdependencyID** | **number** | The unique ID of the Ezsignelementdependency | [default to undefined]
**fkiEzsignformfieldID** | **number** | The unique ID of the Ezsignformfield | [optional] [default to undefined]
**fkiEzsignsignatureID** | **number** | The unique ID of the Ezsignsignature | [optional] [default to undefined]
**fkiEzsignformfieldIDValidation** | **number** | The unique ID of the Ezsignformfield | [optional] [default to undefined]
**fkiEzsignformfieldgroupIDValidation** | **number** | The unique ID of the Ezsignformfieldgroup | [optional] [default to undefined]
**eEzsignelementdependencyValidation** | [**FieldEEzsignelementdependencyValidation**](FieldEEzsignelementdependencyValidation.md) |  | [default to undefined]
**bEzsignelementdependencySelected** | **boolean** | Whether if it\&#39;s selected or not when using eEzsignelementdependencyValidation &#x3D; Selected | [optional] [default to undefined]
**eEzsignelementdependencyOperator** | [**FieldEEzsignelementdependencyOperator**](FieldEEzsignelementdependencyOperator.md) |  | [optional] [default to undefined]
**sEzsignelementdependencyValue** | **string** | The value of the Ezsignelementdependency | [optional] [default to undefined]

## Example

```typescript
import { EzsignelementdependencyResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignelementdependencyResponseCompound = {
    pkiEzsignelementdependencyID,
    fkiEzsignformfieldID,
    fkiEzsignsignatureID,
    fkiEzsignformfieldIDValidation,
    fkiEzsignformfieldgroupIDValidation,
    eEzsignelementdependencyValidation,
    bEzsignelementdependencySelected,
    eEzsignelementdependencyOperator,
    sEzsignelementdependencyValue,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
