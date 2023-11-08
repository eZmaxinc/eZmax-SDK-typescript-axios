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
import { FieldEVariableexpenseTaxable } from './field-evariableexpense-taxable';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualVariableexpenseDescription } from './multilingual-variableexpense-description';

/**
 * A Variableexpense Object
 * @export
 * @interface VariableexpenseResponse
 */
export interface VariableexpenseResponse {
    /**
     * The unique ID of the Variableexpense
     * @type {number}
     * @memberof VariableexpenseResponse
     */
    'pkiVariableexpenseID': number;
    /**
     * The code of the Variableexpense
     * @type {string}
     * @memberof VariableexpenseResponse
     */
    'sVariableexpenseCode'?: string;
    /**
     * 
     * @type {MultilingualVariableexpenseDescription}
     * @memberof VariableexpenseResponse
     */
    'objVariableexpenseDescription': MultilingualVariableexpenseDescription;
    /**
     * 
     * @type {FieldEVariableexpenseTaxable}
     * @memberof VariableexpenseResponse
     */
    'eVariableexpenseTaxable'?: FieldEVariableexpenseTaxable;
    /**
     * Whether the variableexpense is active or not
     * @type {boolean}
     * @memberof VariableexpenseResponse
     */
    'bVariableexpenseIsactive'?: boolean;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualVariableexpenseDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualVariableexpenseDescription } from './'

/**
 * @export 
 * A VariableexpenseResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseResponse
 */
export class DataObjectVariableexpenseResponse {
   pkiVariableexpenseID:number = 0
   sVariableexpenseCode?:string = undefined
   objVariableexpenseDescription:MultilingualVariableexpenseDescription = new DataObjectMultilingualVariableexpenseDescription()
   eVariableexpenseTaxable?:FieldEVariableexpenseTaxable = undefined
   bVariableexpenseIsactive?:boolean = undefined
}

/**
 * @export 
 * A VariableexpenseResponse Validation Object
 * @class ValidationObjectVariableexpenseResponse
 */
export class ValidationObjectVariableexpenseResponse {
   pkiVariableexpenseID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   sVariableexpenseCode = {
      type: 'string',
      pattern: '/^.{0,5}$/',
      required: false
   }
   objVariableexpenseDescription = new ValidationObjectMultilingualVariableexpenseDescription()
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

