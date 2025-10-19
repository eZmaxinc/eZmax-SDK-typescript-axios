# VariableexpenseRequest

A Variableexpense Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiVariableexpenseID** | **number** | The unique ID of the Variableexpense | [optional] [default to undefined]
**sVariableexpenseCode** | **string** | The code of the Variableexpense | [default to undefined]
**objVariableexpenseDescription** | [**MultilingualVariableexpenseDescription**](MultilingualVariableexpenseDescription.md) |  | [default to undefined]
**eVariableexpenseTaxable** | [**FieldEVariableexpenseTaxable**](FieldEVariableexpenseTaxable.md) |  | [default to undefined]
**bVariableexpenseIsactive** | **boolean** | Whether the variableexpense is active or not | [default to undefined]

## Example

```typescript
import { VariableexpenseRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: VariableexpenseRequest = {
    pkiVariableexpenseID,
    sVariableexpenseCode,
    objVariableexpenseDescription,
    eVariableexpenseTaxable,
    bVariableexpenseIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
