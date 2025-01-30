/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignelementdependencyOperator } from './field-eezsignelementdependency-operator';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignelementdependencyValidation } from './field-eezsignelementdependency-validation';

/**
 * An Ezsignelementdependency Object
 * @export
 * @interface EzsignelementdependencyRequest
 */
export interface EzsignelementdependencyRequest {
    /**
     * The unique ID of the Ezsignelementdependency
     * @type {number}
     * @memberof EzsignelementdependencyRequest
     */
    /*'pkiEzsignelementdependencyID'?: number;*/
    'pkiEzsignelementdependencyID'?: number;
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof EzsignelementdependencyRequest
     */
    /*'fkiEzsignformfieldIDValidation'?: number;*/
    'fkiEzsignformfieldIDValidation'?: number;
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignelementdependencyRequest
     */
    /*'fkiEzsignformfieldgroupIDValidation'?: number;*/
    'fkiEzsignformfieldgroupIDValidation'?: number;
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignelementdependencyRequest
     */
    /*'sEzsignelementdependencyEzsignformfieldgrouplabel'?: string;*/
    'sEzsignelementdependencyEzsignformfieldgrouplabel'?: string;
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof EzsignelementdependencyRequest
     */
    /*'sEzsignelementdependencyEzsignformfieldlabel'?: string;*/
    'sEzsignelementdependencyEzsignformfieldlabel'?: string;
    /**
     * 
     * @type {FieldEEzsignelementdependencyValidation}
     * @memberof EzsignelementdependencyRequest
     */
    /*'eEzsignelementdependencyValidation': FieldEEzsignelementdependencyValidation;*/
    'eEzsignelementdependencyValidation': FieldEEzsignelementdependencyValidation;
    /**
     * Whether if it\'s selected or not when using eEzsignelementdependencyValidation = Selected
     * @type {boolean}
     * @memberof EzsignelementdependencyRequest
     */
    /*'bEzsignelementdependencySelected'?: boolean;*/
    'bEzsignelementdependencySelected'?: boolean;
    /**
     * 
     * @type {FieldEEzsignelementdependencyOperator}
     * @memberof EzsignelementdependencyRequest
     */
    /*'eEzsignelementdependencyOperator'?: FieldEEzsignelementdependencyOperator;*/
    'eEzsignelementdependencyOperator'?: FieldEEzsignelementdependencyOperator;
    /**
     * The value of the Ezsignelementdependency
     * @type {string}
     * @memberof EzsignelementdependencyRequest
     */
    /*'sEzsignelementdependencyValue'?: string;*/
    'sEzsignelementdependencyValue'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignelementdependencyRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignelementdependencyRequest
 */
export class DataObjectEzsignelementdependencyRequest {
   pkiEzsignelementdependencyID?:number = undefined
   fkiEzsignformfieldIDValidation?:number = undefined
   fkiEzsignformfieldgroupIDValidation?:number = undefined
   sEzsignelementdependencyEzsignformfieldgrouplabel?:string = undefined
   sEzsignelementdependencyEzsignformfieldlabel?:string = undefined
   eEzsignelementdependencyValidation:FieldEEzsignelementdependencyValidation = 'Value'
   bEzsignelementdependencySelected?:boolean = undefined
   eEzsignelementdependencyOperator?:FieldEEzsignelementdependencyOperator = undefined
   sEzsignelementdependencyValue?:string = undefined
}

/**
 * @export 
 * A EzsignelementdependencyRequest Validation Object
 * @class ValidationObjectEzsignelementdependencyRequest
 */
export class ValidationObjectEzsignelementdependencyRequest {
   pkiEzsignelementdependencyID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiEzsignformfieldIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignformfieldgroupIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignelementdependencyEzsignformfieldgrouplabel = {
      type: 'string',
      minLength: 1,
      maxLength: 50,
      required: false
   }
   sEzsignelementdependencyEzsignformfieldlabel = {
      type: 'string',
      required: false
   }
   eEzsignelementdependencyValidation = {
      type: 'enum',
      allowableValues: ['Value','Selected','Filled'],
      required: true
   }
   bEzsignelementdependencySelected = {
      type: 'boolean',
      required: false
   }
   eEzsignelementdependencyOperator = {
      type: 'enum',
      allowableValues: ['eq','neq','gt','gte','lt','lte','in','nin','rg','like','between'],
      required: false
   }
   sEzsignelementdependencyValue = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
} 


