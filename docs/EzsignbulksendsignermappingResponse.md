# EzsignbulksendsignermappingResponse

A Ezsignbulksendsignermapping Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksendsignermappingID** | **number** | The unique ID of the Ezsignbulksendsignermapping | [default to undefined]
**fkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**bEzsignbulksendsignermappingReceivecopy** | **boolean** | Whether the Ezsignbulksendsigner will receive a copy or not | [optional] [default to undefined]
**sEzsignbulksendsignermappingDescription** | **string** | The description of the Ezsignbulksendsignermapping | [default to undefined]

## Example

```typescript
import { EzsignbulksendsignermappingResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendsignermappingResponse = {
    pkiEzsignbulksendsignermappingID,
    fkiEzsignbulksendID,
    fkiUserID,
    bEzsignbulksendsignermappingReceivecopy,
    sEzsignbulksendsignermappingDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
