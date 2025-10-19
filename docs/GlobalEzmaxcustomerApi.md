# GlobalEzmaxcustomerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**globalEzmaxcustomerGetConfigurationV1**](#globalezmaxcustomergetconfigurationv1) | **GET** /1/ezmaxcustomer/{pksEzmaxcustomerCode}/getConfiguration | Get ezmaxcustomer configuration|

# **globalEzmaxcustomerGetConfigurationV1**
> GlobalEzmaxcustomerGetConfigurationV1Response globalEzmaxcustomerGetConfigurationV1()

Retrieve the ezmaxcustomer\'s specific configuration. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.

### Example

```typescript
import {
    GlobalEzmaxcustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new GlobalEzmaxcustomerApi(configuration);

let pksEzmaxcustomerCode: string; // (default to undefined)

const { status, data } = await apiInstance.globalEzmaxcustomerGetConfigurationV1(
    pksEzmaxcustomerCode
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pksEzmaxcustomerCode** | [**string**] |  | defaults to undefined|


### Return type

**GlobalEzmaxcustomerGetConfigurationV1Response**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

