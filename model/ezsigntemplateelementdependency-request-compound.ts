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
import { EzsigntemplateelementdependencyRequest } from './ezsigntemplateelementdependency-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateelementdependencyOperator } from './field-eezsigntemplateelementdependency-operator';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateelementdependencyValidation } from './field-eezsigntemplateelementdependency-validation';

/**
 * @type EzsigntemplateelementdependencyRequestCompound
 * An Ezsigntemplateelementdependency Object and children to create a complete structure
 * @export
 */
/** export type EzsigntemplateelementdependencyRequestCompound = EzsigntemplateelementdependencyRequest; */
export interface EzsigntemplateelementdependencyRequestCompound {
    /**
     * The unique ID of the Ezsigntemplateelementdependency
     * @type {number}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    pkiEzsigntemplateelementdependencyID?:number 
    /**
     * The unique ID of the Ezsigntemplateformfield
     * @type {number}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    fkiEzsigntemplateformfieldIDValidation?:number 
    /**
     * The unique ID of the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    fkiEzsigntemplateformfieldgroupIDValidation?:number 
    /**
     * The Label for the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    sEzsigntemplateelementdependencyEzsigntemplateformfieldgrouplabel?:string 
    /**
     * The Label for the Ezsigntemplateformfield
     * @type {string}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    sEzsigntemplateelementdependencyEzsigntemplateformfieldlabel?:string 
    /**
     * 
     * @type {FieldEEzsigntemplateelementdependencyValidation}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    eEzsigntemplateelementdependencyValidation:FieldEEzsigntemplateelementdependencyValidation 
    /**
     * Whether if it\'s selected or not when using eEzsigntemplateelementdependencyValidation = Selected
     * @type {boolean}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    bEzsigntemplateelementdependencySelected?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplateelementdependencyOperator}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    eEzsigntemplateelementdependencyOperator?:FieldEEzsigntemplateelementdependencyOperator 
    /**
     * The value of the Ezsignelementdependency
     * @type {string}
     * @memberof EzsigntemplateelementdependencyRequestCompound
     */
    sEzsigntemplateelementdependencyValue?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateelementdependencyRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateelementdependencyRequestCompound
 */
export class DataObjectEzsigntemplateelementdependencyRequestCompound {
    pkiEzsigntemplateelementdependencyID?:number = undefined
    fkiEzsigntemplateformfieldIDValidation?:number = undefined
    fkiEzsigntemplateformfieldgroupIDValidation?:number = undefined
    sEzsigntemplateelementdependencyEzsigntemplateformfieldgrouplabel?:string = undefined
    sEzsigntemplateelementdependencyEzsigntemplateformfieldlabel?:string = undefined
    eEzsigntemplateelementdependencyValidation:FieldEEzsigntemplateelementdependencyValidation = 'Value'
    bEzsigntemplateelementdependencySelected?:boolean = undefined
    eEzsigntemplateelementdependencyOperator?:FieldEEzsigntemplateelementdependencyOperator = undefined
    sEzsigntemplateelementdependencyValue?:string = undefined
}

/**
 * @export 
 * A EzsigntemplateelementdependencyRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplateelementdependencyRequestCompound
 */
export class ValidationObjectEzsigntemplateelementdependencyRequestCompound {
   pkiEzsigntemplateelementdependencyID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzsigntemplateformfieldIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplateformfieldgroupIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsigntemplateelementdependencyEzsigntemplateformfieldgrouplabel = {
      type: 'string',
      required: false
   }
   sEzsigntemplateelementdependencyEzsigntemplateformfieldlabel = {
      type: 'string',
      required: false
   }
   eEzsigntemplateelementdependencyValidation = {
      type: 'enum',
      allowableValues: ['Value','Selected','Filled'],
      required: true
   }
   bEzsigntemplateelementdependencySelected = {
      type: 'boolean',
      required: false
   }
   eEzsigntemplateelementdependencyOperator = {
      type: 'enum',
      allowableValues: ['eq','neq','gt','gte','lt','lte','in','nin','rg','like','between'],
      required: false
   }
   sEzsigntemplateelementdependencyValue = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: false
   }
} 

