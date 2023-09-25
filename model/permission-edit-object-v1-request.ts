/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { PermissionRequestCompound } from './permission-request-compound';

/**
 * Request for PUT /1/object/permission/{pkiPermissionID}
 * @export
 * @interface PermissionEditObjectV1Request
 */
export interface PermissionEditObjectV1Request {
    /**
     * 
     * @type {PermissionRequestCompound}
     * @memberof PermissionEditObjectV1Request
     */
    'objPermission': PermissionRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectPermissionRequestCompound } from './'
// @ts-ignore
import { ValidationObjectPermissionRequestCompound } from './'

/**
 * @export 
 * A PermissionEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPermissionEditObjectV1Request
 */
export class DataObjectPermissionEditObjectV1Request {
   objPermission:PermissionRequestCompound = new DataObjectPermissionRequestCompound()
}

/**
 * @export 
 * A PermissionEditObjectV1Request Validation Object
 * @class ValidationObjectPermissionEditObjectV1Request
 */
export class ValidationObjectPermissionEditObjectV1Request {
   objPermission = new ValidationObjectPermissionRequestCompound()
} 


