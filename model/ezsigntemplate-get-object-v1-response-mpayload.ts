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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentResponse } from './ezsigntemplatedocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerResponseCompound } from './ezsigntemplatesigner-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateType } from './field-eezsigntemplate-type';

/**
 * @type EzsigntemplateGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplate/{pkiEzsigntemplateID}
 * @export
 */
/*export type EzsigntemplateGetObjectV1ResponseMPayload = EzsigntemplateResponseCompound;*/
export interface EzsigntemplateGetObjectV1ResponseMPayload {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    pkiEzsigntemplateID:number 
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    fkiEzsigntemplatedocumentID?:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    fkiEzsignfoldertypeID?:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    fkiLanguageID:number 
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    sLanguageNameX:string 
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    sEzsigntemplateDescription:string 
    /**
     * The filename pattern of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    sEzsigntemplateFilenamepattern?:string 
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    bEzsigntemplateAdminonly:boolean 
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    sEzsignfoldertypeNameX?:string 
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    objAudit:CommonAudit 
    /**
     * Whether the Ezsigntemplate if allowed to edit or not
     * @type {boolean}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    bEzsigntemplateEditallowed:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplateType}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    eEzsigntemplateType?:FieldEEzsigntemplateType 
    /**
     * 
     * @type {EzsigntemplatedocumentResponse}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    objEzsigntemplatedocument?:EzsigntemplatedocumentResponse 
    /**
     * 
     * @type {Array<EzsigntemplatesignerResponseCompound>}
     * @memberof EzsigntemplateGetObjectV1ResponseMPayload
     */
    a_objEzsigntemplatesigner:Array<EzsigntemplatesignerResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { DataObjectEzsigntemplatedocumentResponse } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentResponse } from './'

/**
 * @export 
 * A EzsigntemplateGetObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateGetObjectV1ResponseMPayload
 */
export class DataObjectEzsigntemplateGetObjectV1ResponseMPayload {
    pkiEzsigntemplateID:number = 0
    fkiEzsigntemplatedocumentID?:number = undefined
    fkiEzsignfoldertypeID?:number = undefined
    fkiLanguageID:number = 0
    sLanguageNameX:string = ''
    sEzsigntemplateDescription:string = ''
    sEzsigntemplateFilenamepattern?:string = undefined
    bEzsigntemplateAdminonly:boolean = false
    sEzsignfoldertypeNameX?:string = undefined
    objAudit:CommonAudit = new DataObjectCommonAudit()
    bEzsigntemplateEditallowed:boolean = false
    eEzsigntemplateType?:FieldEEzsigntemplateType = undefined
    objEzsigntemplatedocument?:EzsigntemplatedocumentResponse = undefined
    a_objEzsigntemplatesigner:Array<EzsigntemplatesignerResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplateGetObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplateGetObjectV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplateGetObjectV1ResponseMPayload {
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
      maximum: 65535,
      required: false
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
   sEzsigntemplateFilenamepattern = {
      type: 'string',
      pattern: '/^.{1,50}$/',
      required: false
   }
   bEzsigntemplateAdminonly = {
      type: 'boolean',
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
   bEzsigntemplateEditallowed = {
      type: 'boolean',
      required: true
   }
   eEzsigntemplateType = {
      type: 'enum',
      allowableValues: ['User','Usergroup','Company'],
      required: false
   }
   objEzsigntemplatedocument = new ValidationObjectEzsigntemplatedocumentResponse()
   a_objEzsigntemplatesigner = {
      type: 'array',
      required: true
   }
} 


