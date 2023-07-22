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
import { VariableexpenseListElement } from './variableexpense-list-element';

/**
 * 
 * @export
 * @interface VariableexpenseGetListV1ResponseMPayloadAllOf
 */
export interface VariableexpenseGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<VariableexpenseListElement>}
     * @memberof VariableexpenseGetListV1ResponseMPayloadAllOf
     */
    'a_objVariableexpense': Array<VariableexpenseListElement>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A VariableexpenseGetListV1ResponseMPayloadAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseGetListV1ResponseMPayloadAllOf
 */
export class DataObjectVariableexpenseGetListV1ResponseMPayloadAllOf {
   a_objVariableexpense:Array<VariableexpenseListElement> = []
}

/**
 * @export 
 * A VariableexpenseGetListV1ResponseMPayloadAllOf Validation Object
 * @class ValidationObjectVariableexpenseGetListV1ResponseMPayloadAllOf
 */
export class ValidationObjectVariableexpenseGetListV1ResponseMPayloadAllOf {
   a_objVariableexpense = {
      type: 'array',
      required: true
   }
} 


