# VariableexpenseListElement

A Variableexpense List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiVariableexpenseID** | **number** | The unique ID of the Variableexpense | [default to undefined]
**sVariableexpenseCode** | **string** | The code of the Variableexpense | [optional] [default to undefined]
**sVariableexpenseDescriptionX** | **string** | The description of the Variableexpense in the language of the requester | [optional] [default to undefined]
**eVariableexpenseTaxable** | [**FieldEVariableexpenseTaxable**](FieldEVariableexpenseTaxable.md) |  | [optional] [default to undefined]
**bVariableexpenseIsactive** | **boolean** | Whether the variableexpense is active or not | [optional] [default to undefined]

## Example

```typescript
import { VariableexpenseListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: VariableexpenseListElement = {
    pkiVariableexpenseID,
    sVariableexpenseCode,
    sVariableexpenseDescriptionX,
    eVariableexpenseTaxable,
    bVariableexpenseIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
