# SupplyRequest

A Supply Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSupplyID** | **number** | The unique ID of the Supply | [optional] [default to undefined]
**fkiGlaccountID** | **number** | The unique ID of the Glaccount | [optional] [default to undefined]
**fkiGlaccountcontainerID** | **number** | The unique ID of the Glaccountcontainer | [optional] [default to undefined]
**fkiVariableexpenseID** | **number** | The unique ID of the Variableexpense | [default to undefined]
**sSupplyCode** | **string** | The code of the Supply | [default to undefined]
**objSupplyDescription** | [**MultilingualSupplyDescription**](MultilingualSupplyDescription.md) |  | [default to undefined]
**dSupplyUnitprice** | **string** | The unit price of the Supply | [default to undefined]
**bSupplyIsactive** | **boolean** | Whether the supply is active or not | [default to undefined]
**bSupplyVariableprice** | **boolean** | Whether if the price is variable | [default to undefined]

## Example

```typescript
import { SupplyRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SupplyRequest = {
    pkiSupplyID,
    fkiGlaccountID,
    fkiGlaccountcontainerID,
    fkiVariableexpenseID,
    sSupplyCode,
    objSupplyDescription,
    dSupplyUnitprice,
    bSupplyIsactive,
    bSupplyVariableprice,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
