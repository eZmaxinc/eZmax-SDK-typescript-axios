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
import { CommonFile } from './common-file';

/**
 * Request for POST /1/object/ezsignsignature/{pkiEzsignsignatureID}/sign
 * @export
 * @interface EzsignsignatureSignV1Request
 */
export interface EzsignsignatureSignV1Request {
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'fkiEzsignsigningreasonID'?: number;*/
    'fkiEzsignsigningreasonID'?: number;
    /**
     * The value required for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **City**, **FieldText** or **FieldTextarea**
     * @type {string}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'sValue'?: string;*/
    'sValue'?: string;
    /**
     * Whether the attachment are accepted or refused.  This can only be set if eEzsignsignatureType is **AttachmentsConfirmation**
     * @type {string}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'eAttachmentsConfirmationDecision'?: EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum;*/
    'eAttachmentsConfirmationDecision'?: EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum;
    /**
     * The reason of refused.  This can only be set if eEzsignsignatureType is **AttachmentsConfirmation**
     * @type {string}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'sAttachmentsRefusalReason'?: string;*/
    'sAttachmentsRefusalReason'?: string;
    /**
     * The SVG of the handwritten signature.  This can only be set if eEzsignsignatureType is **Handwritten** and **bIsAutomatic** is false
     * @type {string}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'sSvg'?: string;*/
    'sSvg'?: string;
    /**
     * 
     * @type {Array<CommonFile>}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'a_objFile'?: Array<CommonFile>;*/
    'a_objFile'?: Array<CommonFile>;
    /**
     * Indicates if the Ezsignsignature was part of an automatic process or not.  This can only be true if eEzsignsignatureType is **Acknowledgement**, **City**, **Handwritten**, **Initials**, **Name** or **Stamp**. 
     * @type {boolean}
     * @memberof EzsignsignatureSignV1Request
     */
    /*'bIsAutomatic': boolean;*/
    'bIsAutomatic': boolean;
}

export const EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum = {
    Accepted: 'Accepted',
    Refused: 'Refused'
} as const;
export type EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum = typeof EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum[keyof typeof EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignatureSignV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureSignV1Request
 */
export class DataObjectEzsignsignatureSignV1Request {
   fkiEzsignsigningreasonID?:number = undefined
   sValue?:string = undefined
   eAttachmentsConfirmationDecision?:EzsignsignatureSignV1RequestEAttachmentsConfirmationDecisionEnum = undefined
   sAttachmentsRefusalReason?:string = undefined
   sSvg?:string = undefined
   a_objFile?:Array<CommonFile> = undefined
   bIsAutomatic:boolean = false
}

/**
 * @export 
 * A EzsignsignatureSignV1Request Validation Object
 * @class ValidationObjectEzsignsignatureSignV1Request
 */
export class ValidationObjectEzsignsignatureSignV1Request {
   fkiEzsignsigningreasonID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   sValue = {
      type: 'string',
      required: false
   }
   eAttachmentsConfirmationDecision = {
      type: 'string',
      required: false
   }
   sAttachmentsRefusalReason = {
      type: 'string',
      required: false
   }
   sSvg = {
      type: 'string',
      pattern: '/^.{0,65535}$/',
      required: false
   }
   a_objFile = {
      type: 'array',
      required: false
   }
   bIsAutomatic = {
      type: 'boolean',
      required: true
   }
} 


