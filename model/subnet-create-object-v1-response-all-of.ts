/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { SubnetCreateObjectV1ResponseMPayload } from './subnet-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface SubnetCreateObjectV1ResponseAllOf
 */
export interface SubnetCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {SubnetCreateObjectV1ResponseMPayload}
     * @memberof SubnetCreateObjectV1ResponseAllOf
     */
    'mPayload': SubnetCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectSubnetCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectSubnetCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A SubnetCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSubnetCreateObjectV1ResponseAllOf
 */
export class DataObjectSubnetCreateObjectV1ResponseAllOf {
   mPayload:SubnetCreateObjectV1ResponseMPayload = new DataObjectSubnetCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A SubnetCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectSubnetCreateObjectV1ResponseAllOf
 */
export class ValidationObjectSubnetCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectSubnetCreateObjectV1ResponseMPayload()
} 


