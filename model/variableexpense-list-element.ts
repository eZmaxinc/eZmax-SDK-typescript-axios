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
import { FieldEVariableexpenseTaxable } from './field-evariableexpense-taxable';

/**
 * A Variableexpense List Element
 * @export
 * @interface VariableexpenseListElement
 */
export interface VariableexpenseListElement {
    /**
     * The unique ID of the Variableexpense
     * @type {number}
     * @memberof VariableexpenseListElement
     */
    /*'pkiVariableexpenseID': number;*/
    'pkiVariableexpenseID': number;
    /**
     * The code of the Variableexpense
     * @type {string}
     * @memberof VariableexpenseListElement
     */
    /*'sVariableexpenseCode'?: string;*/
    'sVariableexpenseCode'?: string;
    /**
     * The description of the Variableexpense in the language of the requester
     * @type {string}
     * @memberof VariableexpenseListElement
     */
    /*'sVariableexpenseDescriptionX'?: string;*/
    'sVariableexpenseDescriptionX'?: string;
    /**
     * 
     * @type {FieldEVariableexpenseTaxable}
     * @memberof VariableexpenseListElement
     */
    /*'eVariableexpenseTaxable'?: FieldEVariableexpenseTaxable;*/
    'eVariableexpenseTaxable'?: FieldEVariableexpenseTaxable;
    /**
     * Whether the variableexpense is active or not
     * @type {boolean}
     * @memberof VariableexpenseListElement
     */
    /*'bVariableexpenseIsactive'?: boolean;*/
    'bVariableexpenseIsactive'?: boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A VariableexpenseListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseListElement
 */
export class DataObjectVariableexpenseListElement {
   pkiVariableexpenseID:number = 0
   sVariableexpenseCode?:string = undefined
   sVariableexpenseDescriptionX?:string = undefined
   eVariableexpenseTaxable?:FieldEVariableexpenseTaxable = undefined
   bVariableexpenseIsactive?:boolean = undefined
}

/**
 * @export 
 * A VariableexpenseListElement Validation Object
 * @class ValidationObjectVariableexpenseListElement
 */
export class ValidationObjectVariableexpenseListElement {
   pkiVariableexpenseID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   sVariableexpenseCode = {
      type: 'string',
      pattern: /^.{0,5}$/,
      required: false
   }
   sVariableexpenseDescriptionX = {
      type: 'string',
      pattern: /^.{0,40}$/,
      required: false
   }
   eVariableexpenseTaxable = {
      type: 'enum',
      allowableValues: ['Yes','No','Included'],
      required: false
   }
   bVariableexpenseIsactive = {
      type: 'boolean',
      required: false
   }
} 


