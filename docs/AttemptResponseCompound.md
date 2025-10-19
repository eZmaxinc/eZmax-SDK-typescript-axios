# AttemptResponseCompound

An Attempt object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**dtAttemptStart** | **string** | Represent a Date Time. The timezone is the one configured in the User\&#39;s profile. | [default to undefined]
**sAttemptResult** | **string** | The Success or Failure message of the attempt when we tried to call the URL to deliver the webhook event. | [default to undefined]
**iAttemptDuration** | **number** | The number of second it took to process the webhook or get an error | [default to undefined]

## Example

```typescript
import { AttemptResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttemptResponseCompound = {
    dtAttemptStart,
    sAttemptResult,
    iAttemptDuration,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
