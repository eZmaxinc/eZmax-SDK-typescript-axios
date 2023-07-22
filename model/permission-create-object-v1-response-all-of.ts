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
import { PermissionCreateObjectV1ResponseMPayload } from './permission-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface PermissionCreateObjectV1ResponseAllOf
 */
export interface PermissionCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {PermissionCreateObjectV1ResponseMPayload}
     * @memberof PermissionCreateObjectV1ResponseAllOf
     */
    'mPayload': PermissionCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectPermissionCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectPermissionCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A PermissionCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPermissionCreateObjectV1ResponseAllOf
 */
export class DataObjectPermissionCreateObjectV1ResponseAllOf {
   mPayload:PermissionCreateObjectV1ResponseMPayload = new DataObjectPermissionCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A PermissionCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectPermissionCreateObjectV1ResponseAllOf
 */
export class ValidationObjectPermissionCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectPermissionCreateObjectV1ResponseMPayload()
} 


