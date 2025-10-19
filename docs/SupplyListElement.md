# SupplyListElement

A Supply List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSupplyID** | **number** | The unique ID of the Supply | [default to undefined]
**fkiGlaccountID** | **number** | The unique ID of the Glaccount | [optional] [default to undefined]
**fkiGlaccountcontainerID** | **number** | The unique ID of the Glaccountcontainer | [optional] [default to undefined]
**fkiVariableexpenseID** | **number** | The unique ID of the Variableexpense | [default to undefined]
**sSupplyCode** | **string** | The code of the Supply | [default to undefined]
**sSupplyDescriptionX** | **string** | The description of the Supply in the language of the requester | [default to undefined]
**dSupplyUnitprice** | **string** | The unit price of the Supply | [default to undefined]
**bSupplyIsactive** | **boolean** | Whether the supply is active or not | [default to undefined]
**bSupplyVariableprice** | **boolean** | Whether if the price is variable | [default to undefined]
**sGlaccountDescriptionX** | **string** | The Description for the Glaccount in the language of the requester | [optional] [default to undefined]
**sGlaccountcontainerLongdescriptionX** | **string** | The Description for the Glaccountcontainer in the language of the requester | [optional] [default to undefined]
**sVariableexpenseDescriptionX** | **string** | The description of the Variableexpense in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { SupplyListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SupplyListElement = {
    pkiSupplyID,
    fkiGlaccountID,
    fkiGlaccountcontainerID,
    fkiVariableexpenseID,
    sSupplyCode,
    sSupplyDescriptionX,
    dSupplyUnitprice,
    bSupplyIsactive,
    bSupplyVariableprice,
    sGlaccountDescriptionX,
    sGlaccountcontainerLongdescriptionX,
    sVariableexpenseDescriptionX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
