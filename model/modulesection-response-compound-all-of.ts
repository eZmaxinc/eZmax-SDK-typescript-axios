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
import { PermissionResponseCompound } from './permission-response-compound';

/**
 * 
 * @export
 * @interface ModulesectionResponseCompoundAllOf
 */
export interface ModulesectionResponseCompoundAllOf {
    /**
     * 
     * @type {Array<PermissionResponseCompound>}
     * @memberof ModulesectionResponseCompoundAllOf
     */
    'a_objPermission'?: Array<PermissionResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ModulesectionResponseCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModulesectionResponseCompoundAllOf
 */
export class DataObjectModulesectionResponseCompoundAllOf {
   a_objPermission?:Array<PermissionResponseCompound> = undefined
}

/**
 * @export 
 * A ModulesectionResponseCompoundAllOf Validation Object
 * @class ValidationObjectModulesectionResponseCompoundAllOf
 */
export class ValidationObjectModulesectionResponseCompoundAllOf {
   a_objPermission = {
      type: 'array',
      required: false
   }
} 


