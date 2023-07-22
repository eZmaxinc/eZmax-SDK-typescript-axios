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
import { FieldEVariableexpenseTaxable } from './field-evariableexpense-taxable';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualVariableexpenseDescription } from './multilingual-variableexpense-description';
// May contain unused imports in some cases
// @ts-ignore
import { VariableexpenseResponse } from './variableexpense-response';

/**
 * @type VariableexpenseResponseCompound
 * A Variableexpense Object
 * @export
 */
export type VariableexpenseResponseCompound = VariableexpenseResponse;



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
 * A VariableexpenseResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseResponseCompound
 */
export class DataObjectVariableexpenseResponseCompound {
    pkiVariableexpenseID:number = 0
    sVariableexpenseCode?:string = undefined
    objVariableexpenseDescription:MultilingualVariableexpenseDescription = new DataObjectMultilingualVariableexpenseDescription()
    eVariableexpenseTaxable?:FieldEVariableexpenseTaxable = undefined
    bVariableexpenseIsactive?:boolean = undefined
}

/**
 * @export 
 * A VariableexpenseResponseCompound Validation Object
 * @class ValidationObjectVariableexpenseResponseCompound
 */
export class ValidationObjectVariableexpenseResponseCompound {
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


