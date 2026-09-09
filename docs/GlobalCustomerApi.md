# GlobalCustomerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**globalCustomerGetEndpointV1**](#globalcustomergetendpointv1) | **GET** /1/customer/{pksCustomerCode}/endpoint | Get customer endpoint|

# **globalCustomerGetEndpointV1**
> GlobalCustomerGetEndpointV1Response globalCustomerGetEndpointV1()

Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.

### Example

```typescript
import {
    GlobalCustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new GlobalCustomerApi(configuration);

let pksCustomerCode: string; // (default to undefined)
let sInfrastructureproductCode: 'appcluster01' | 'ezsignuser'; //The infrastructure product Code  If undefined, \"appcluster01\" is assumed (optional) (default to undefined)

const { status, data } = await apiInstance.globalCustomerGetEndpointV1(
    pksCustomerCode,
    sInfrastructureproductCode
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pksCustomerCode** | [**string**] |  | defaults to undefined|
| **sInfrastructureproductCode** | [**&#39;appcluster01&#39; | &#39;ezsignuser&#39;**]**Array<&#39;appcluster01&#39; &#124; &#39;ezsignuser&#39;>** | The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed | (optional) defaults to undefined|


### Return type

**GlobalCustomerGetEndpointV1Response**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

