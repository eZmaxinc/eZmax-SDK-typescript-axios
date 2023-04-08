/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';

/**
 * A Ezsigntemplate Object
 * @export
 * @interface EzsigntemplateResponse
 */
export interface EzsigntemplateResponse {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'pkiEzsigntemplateID': number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'fkiEzsigntemplatedocumentID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'fkiLanguageID': number;
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateResponse
     */
    'sLanguageNameX': string;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateResponse
     */
    'sEzsigntemplateDescription': string;
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateResponse
     */
    'bEzsigntemplateAdminonly': boolean;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateResponse
     */
    'sEzsignfoldertypeNameX': string;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsigntemplateResponse
     */
    'objAudit': CommonAudit;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzsigntemplateResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateResponse
 */
export class DataObjectEzsigntemplateResponse {
   pkiEzsigntemplateID:number = 0
   fkiEzsigntemplatedocumentID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   sEzsigntemplateDescription:string = ''
   bEzsigntemplateAdminonly:boolean = false
   sEzsignfoldertypeNameX:string = ''
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A EzsigntemplateResponse Validation Object
 * @class ValidationObjectEzsigntemplateResponse
 */
export class ValidationObjectEzsigntemplateResponse {
   pkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sLanguageNameX = {
      type: 'string',
      required: true
   }
   sEzsigntemplateDescription = {
      type: 'string',
      required: true
   }
   bEzsigntemplateAdminonly = {
      type: 'boolean',
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


