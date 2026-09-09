# ObjectSubnetApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**subnetCreateObjectV1**](#subnetcreateobjectv1) | **POST** /1/object/subnet | Create a new Subnet|
|[**subnetDeleteObjectV1**](#subnetdeleteobjectv1) | **DELETE** /1/object/subnet/{pkiSubnetID} | Delete an existing Subnet|
|[**subnetEditObjectV1**](#subneteditobjectv1) | **PUT** /1/object/subnet/{pkiSubnetID} | Edit an existing Subnet|
|[**subnetGetObjectV2**](#subnetgetobjectv2) | **GET** /2/object/subnet/{pkiSubnetID} | Retrieve an existing Subnet|

# **subnetCreateObjectV1**
> SubnetCreateObjectV1Response subnetCreateObjectV1(subnetCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectSubnetApi,
    Configuration,
    SubnetCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSubnetApi(configuration);

let subnetCreateObjectV1Request: SubnetCreateObjectV1Request; //

const { status, data } = await apiInstance.subnetCreateObjectV1(
    subnetCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **subnetCreateObjectV1Request** | **SubnetCreateObjectV1Request**|  | |


### Return type

**SubnetCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **subnetDeleteObjectV1**
> SubnetDeleteObjectV1Response subnetDeleteObjectV1()



### Example

```typescript
import {
    ObjectSubnetApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSubnetApi(configuration);

let pkiSubnetID: number; //The unique ID of the Subnet (default to undefined)

const { status, data } = await apiInstance.subnetDeleteObjectV1(
    pkiSubnetID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSubnetID** | [**number**] | The unique ID of the Subnet | defaults to undefined|


### Return type

**SubnetDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **subnetEditObjectV1**
> SubnetEditObjectV1Response subnetEditObjectV1(subnetEditObjectV1Request)



### Example

```typescript
import {
    ObjectSubnetApi,
    Configuration,
    SubnetEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSubnetApi(configuration);

let pkiSubnetID: number; //The unique ID of the Subnet (default to undefined)
let subnetEditObjectV1Request: SubnetEditObjectV1Request; //

const { status, data } = await apiInstance.subnetEditObjectV1(
    pkiSubnetID,
    subnetEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **subnetEditObjectV1Request** | **SubnetEditObjectV1Request**|  | |
| **pkiSubnetID** | [**number**] | The unique ID of the Subnet | defaults to undefined|


### Return type

**SubnetEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **subnetGetObjectV2**
> SubnetGetObjectV2Response subnetGetObjectV2()



### Example

```typescript
import {
    ObjectSubnetApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSubnetApi(configuration);

let pkiSubnetID: number; //The unique ID of the Subnet (default to undefined)

const { status, data } = await apiInstance.subnetGetObjectV2(
    pkiSubnetID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSubnetID** | [**number**] | The unique ID of the Subnet | defaults to undefined|


### Return type

**SubnetGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

