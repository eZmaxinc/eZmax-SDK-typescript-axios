/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { VariableexpenseRequestCompound } from './variableexpense-request-compound';

/**
 * Request for POST /1/object/variableexpense
 * @export
 * @interface VariableexpenseCreateObjectV1Request
 */
export interface VariableexpenseCreateObjectV1Request {
    /**
     * 
     * @type {Array<VariableexpenseRequestCompound>}
     * @memberof VariableexpenseCreateObjectV1Request
     */
    /*'a_objVariableexpense': Array<VariableexpenseRequestCompound>;*/
    'a_objVariableexpense': Array<VariableexpenseRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A VariableexpenseCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseCreateObjectV1Request
 */
export class DataObjectVariableexpenseCreateObjectV1Request {
   a_objVariableexpense:Array<VariableexpenseRequestCompound> = []
}

/**
 * @export 
 * A VariableexpenseCreateObjectV1Request Validation Object
 * @class ValidationObjectVariableexpenseCreateObjectV1Request
 */
export class ValidationObjectVariableexpenseCreateObjectV1Request {
   a_objVariableexpense = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


