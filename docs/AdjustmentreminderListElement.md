# AdjustmentreminderListElement

A Adjustmentreminder List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiAdjustmentreminderID** | **number** | The unique ID of the Adjustmentreminder | [default to undefined]
**fkiAdjustmentID** | **number** | The unique ID of the Adjustment | [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**sPeriodYYYYMM** | **string** | The YYYYMM of the Period | [optional] [default to undefined]
**fkiUserIDCreated** | **number** | The unique ID of the User | [optional] [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [optional] [default to undefined]
**eAdjustmentreminderType** | [**FieldEAdjustmentreminderType**](FieldEAdjustmentreminderType.md) |  | [default to undefined]
**sAdjustmentNumber** | **string** | The number of the Adjustment | [optional] [default to undefined]
**sAdjustmentComment** | **string** | The comment of the Adjustment | [optional] [default to undefined]
**dAdjustmentTotaldebit** | **string** | The total debit of Adjustment | [optional] [default to undefined]
**dAdjustmentTotalcredit** | **string** | The total credit of Adjustment | [optional] [default to undefined]

## Example

```typescript
import { AdjustmentreminderListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AdjustmentreminderListElement = {
    pkiAdjustmentreminderID,
    fkiAdjustmentID,
    fkiPeriodID,
    sPeriodYYYYMM,
    fkiUserIDCreated,
    sUserLoginname,
    eAdjustmentreminderType,
    sAdjustmentNumber,
    sAdjustmentComment,
    dAdjustmentTotaldebit,
    dAdjustmentTotalcredit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
