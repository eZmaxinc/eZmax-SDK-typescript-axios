# EmailResponseCompound

An Email Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEmailID** | **number** | The unique ID of the Email | [default to undefined]
**fkiEmailtypeID** | **number** | The unique ID of the Emailtype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| | [default to undefined]
**sEmailAddress** | **string** | The email address. | [default to undefined]

## Example

```typescript
import { EmailResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EmailResponseCompound = {
    pkiEmailID,
    fkiEmailtypeID,
    sEmailAddress,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
