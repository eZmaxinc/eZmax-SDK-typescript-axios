# SubnetRequestCompound

A Subnet Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSubnetID** | **number** | The unique ID of the Subnet | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiApikeyID** | **number** | The unique ID of the Apikey | [optional] [default to undefined]
**objSubnetDescription** | [**MultilingualSubnetDescription**](MultilingualSubnetDescription.md) |  | [default to undefined]
**iSubnetNetwork** | **number** | The network of the Subnet in integer form. For example 8.8.8.0 would be 134744064 | [default to undefined]
**iSubnetMask** | **number** | The mask of the Subnet  in integer form. For example 255.255.255.0 would be 4294967040 | [default to undefined]

## Example

```typescript
import { SubnetRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SubnetRequestCompound = {
    pkiSubnetID,
    fkiUserID,
    fkiApikeyID,
    objSubnetDescription,
    iSubnetNetwork,
    iSubnetMask,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
