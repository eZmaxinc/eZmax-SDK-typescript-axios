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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

/**
 * An Ezsignbulksend Object
 * @export
 * @interface EzsignbulksendResponse
 */
export interface EzsignbulksendResponse {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendResponse
     */
    'pkiEzsignbulksendID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendResponse
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignbulksendResponse
     */
    'fkiLanguageID': number;
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'sLanguageNameX': string;
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignbulksendResponse
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'sEzsignfoldertypeNameX': string;
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'sEzsignbulksendDescription': string;
    /**
     * Note about the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'tEzsignbulksendNote': string;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendResponse
     */
    'bEzsignbulksendNeedvalidation': boolean;
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendResponse
     */
    'bEzsignbulksendIsactive': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignbulksendResponse
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
 * A EzsignbulksendResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendResponse
 */
export class DataObjectEzsignbulksendResponse {
   pkiEzsignbulksendID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsignfoldertypeNameX:string = ''
   sEzsignbulksendDescription:string = ''
   tEzsignbulksendNote:string = ''
   bEzsignbulksendNeedvalidation:boolean = false
   bEzsignbulksendIsactive:boolean = false
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A EzsignbulksendResponse Validation Object
 * @class ValidationObjectEzsignbulksendResponse
 */
export class ValidationObjectEzsignbulksendResponse {
   pkiEzsignbulksendID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
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
   eEzsignfoldertypePrivacylevel = {
      type: 'enum',
      allowableValues: ['User','Usergroup'],
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   sEzsignbulksendDescription = {
      type: 'string',
      required: true
   }
   tEzsignbulksendNote = {
      type: 'string',
      required: true
   }
   bEzsignbulksendNeedvalidation = {
      type: 'boolean',
      required: true
   }
   bEzsignbulksendIsactive = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


