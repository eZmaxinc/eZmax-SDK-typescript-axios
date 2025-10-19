# ObjectEzmaxcustomerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezmaxcustomerPatchObjectV1**](#ezmaxcustomerpatchobjectv1) | **PATCH** /1/object/ezmaxcustomer/{pkiEzmaxcustomerID} | Patch an existing Ezmaxcustomer|

# **ezmaxcustomerPatchObjectV1**
> EzmaxcustomerPatchObjectV1Response ezmaxcustomerPatchObjectV1(ezmaxcustomerPatchObjectV1Request)



### Example

```typescript
import {
    ObjectEzmaxcustomerApi,
    Configuration,
    EzmaxcustomerPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxcustomerApi(configuration);

let pkiEzmaxcustomerID: number; //The unique ID of the Ezmaxcustomer (default to undefined)
let ezmaxcustomerPatchObjectV1Request: EzmaxcustomerPatchObjectV1Request; //

const { status, data } = await apiInstance.ezmaxcustomerPatchObjectV1(
    pkiEzmaxcustomerID,
    ezmaxcustomerPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezmaxcustomerPatchObjectV1Request** | **EzmaxcustomerPatchObjectV1Request**|  | |
| **pkiEzmaxcustomerID** | [**number**] | The unique ID of the Ezmaxcustomer | defaults to undefined|


### Return type

**EzmaxcustomerPatchObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

