# EzsignbulksendsignermappingRequestV2

A Ezsignbulksendsignermapping Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksendsignermappingID** | **number** | The unique ID of the Ezsignbulksendsignermapping | [optional] [default to undefined]
**fkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**eEzsignbulksendsignermappingRole** | [**FieldEEzsignbulksendsignermappingRole**](FieldEEzsignbulksendsignermappingRole.md) |  | [optional] [default to undefined]
**sEzsignbulksendsignermappingDescription** | **string** | The description of the Ezsignbulksendsignermapping | [default to undefined]

## Example

```typescript
import { EzsignbulksendsignermappingRequestV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendsignermappingRequestV2 = {
    pkiEzsignbulksendsignermappingID,
    fkiEzsignbulksendID,
    fkiUserID,
    eEzsignbulksendsignermappingRole,
    sEzsignbulksendsignermappingDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
