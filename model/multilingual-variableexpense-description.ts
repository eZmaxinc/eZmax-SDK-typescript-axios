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



/**
 * The description of the Variableexpense
 * @export
 * @interface MultilingualVariableexpenseDescription
 */
export interface MultilingualVariableexpenseDescription {
    /**
     * The description of the Variableexpense in French
     * @type {string}
     * @memberof MultilingualVariableexpenseDescription
     */
    'sVariableexpenseDescription1'?: string;
    /**
     * The description of the Variableexpense in English
     * @type {string}
     * @memberof MultilingualVariableexpenseDescription
     */
    'sVariableexpenseDescription2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualVariableexpenseDescription Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualVariableexpenseDescription
 */
export class DataObjectMultilingualVariableexpenseDescription {
   sVariableexpenseDescription1?:string = undefined
   sVariableexpenseDescription2?:string = undefined
}

/**
 * @export 
 * A MultilingualVariableexpenseDescription Validation Object
 * @class ValidationObjectMultilingualVariableexpenseDescription
 */
export class ValidationObjectMultilingualVariableexpenseDescription {
   sVariableexpenseDescription1 = {
      type: 'string',
      pattern: '/^.{0,40}$/',
      required: false
   }
   sVariableexpenseDescription2 = {
      type: 'string',
      pattern: '/^.{0,40}$/',
      required: false
   }
} 


