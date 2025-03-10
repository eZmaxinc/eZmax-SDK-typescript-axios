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
import type { FieldEEzsigntemplateType } from './field-eezsigntemplate-type';

/**
 * A Ezsigntemplate List Element
 * @export
 * @interface EzsigntemplateListElement
 */
export interface EzsigntemplateListElement {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    /*'pkiEzsigntemplateID': number;*/
    'pkiEzsigntemplateID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    /*'fkiEzsignfoldertypeID'?: number;*/
    'fkiEzsignfoldertypeID'?: number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateListElement
     */
    /*'sEzsigntemplateDescription': string;*/
    'sEzsigntemplateDescription': string;
    /**
     * The number of pages in the Ezsigntemplatedocument.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    /*'iEzsigntemplatedocumentPagetotal'?: number;*/
    'iEzsigntemplatedocumentPagetotal'?: number;
    /**
     * The number of total signatures in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    /*'iEzsigntemplateSignaturetotal'?: number;*/
    'iEzsigntemplateSignaturetotal'?: number;
    /**
     * The number of total form fields in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    /*'iEzsigntemplateFormfieldtotal'?: number;*/
    'iEzsigntemplateFormfieldtotal'?: number;
    /**
     * Indicate the Ezsigntemplate is incomplete and cannot be used
     * @type {boolean}
     * @memberof EzsigntemplateListElement
     */
    /*'bEzsigntemplateIncomplete': boolean;*/
    'bEzsigntemplateIncomplete': boolean;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateListElement
     */
    /*'sEzsignfoldertypeNameX'?: string;*/
    'sEzsignfoldertypeNameX'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplateType}
     * @memberof EzsigntemplateListElement
     */
    /*'eEzsigntemplateType': FieldEEzsigntemplateType;*/
    'eEzsigntemplateType': FieldEEzsigntemplateType;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateListElement
 */
export class DataObjectEzsigntemplateListElement {
   pkiEzsigntemplateID:number = 0
   fkiEzsignfoldertypeID?:number = undefined
   fkiLanguageID:number = 0
   sEzsigntemplateDescription:string = ''
   iEzsigntemplatedocumentPagetotal?:number = undefined
   iEzsigntemplateSignaturetotal?:number = undefined
   iEzsigntemplateFormfieldtotal?:number = undefined
   bEzsigntemplateIncomplete:boolean = false
   sEzsignfoldertypeNameX?:string = undefined
   eEzsigntemplateType:FieldEEzsigntemplateType = 'User'
}

/**
 * @export 
 * A EzsigntemplateListElement Validation Object
 * @class ValidationObjectEzsigntemplateListElement
 */
export class ValidationObjectEzsigntemplateListElement {
   pkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sEzsigntemplateDescription = {
      type: 'string',
      pattern: /^.{0,80}$/,
      required: true
   }
   iEzsigntemplatedocumentPagetotal = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   iEzsigntemplateSignaturetotal = {
      type: 'integer',
      required: false
   }
   iEzsigntemplateFormfieldtotal = {
      type: 'integer',
      required: false
   }
   bEzsigntemplateIncomplete = {
      type: 'boolean',
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   eEzsigntemplateType = {
      type: 'enum',
      allowableValues: ['User','Usergroup','Company','Ezsignfoldertype'],
      required: true
   }
} 


