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
import { CommunicationRequest } from './communication-request';
// May contain unused imports in some cases
// @ts-ignore
import { CommunicationexternalrecipientRequestCompound } from './communicationexternalrecipient-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CommunicationrecipientRequestCompound } from './communicationrecipient-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CommunicationreferenceRequestCompound } from './communicationreference-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CustomCommunicationattachmentRequest } from './custom-communicationattachment-request';
// May contain unused imports in some cases
// @ts-ignore
import { CustomCommunicationsenderRequest } from './custom-communicationsender-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationImportance } from './field-ecommunication-importance';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationType } from './field-ecommunication-type';

/**
 * @type CommunicationRequestCompound
 * Request for POST /1/object/communication
 * @export
 */
/*export type CommunicationRequestCompound = CommunicationRequest;*/
export interface CommunicationRequestCompound {
    /**
     * The unique ID of the Communication.
     * @type {number}
     * @memberof CommunicationRequestCompound
     */
    pkiCommunicationID?:number 
    /**
     * 
     * @type {FieldECommunicationImportance}
     * @memberof CommunicationRequestCompound
     */
    eCommunicationImportance?:FieldECommunicationImportance 
    /**
     * 
     * @type {FieldECommunicationType}
     * @memberof CommunicationRequestCompound
     */
    eCommunicationType:FieldECommunicationType 
    /**
     * 
     * @type {CustomCommunicationsenderRequest}
     * @memberof CommunicationRequestCompound
     */
    objCommunicationsender?:CustomCommunicationsenderRequest 
    /**
     * The subject of the Communication
     * @type {string}
     * @memberof CommunicationRequestCompound
     */
    sCommunicationSubject?:string 
    /**
     * The Body of the Communication
     * @type {string}
     * @memberof CommunicationRequestCompound
     */
    tCommunicationBody:string 
    /**
     * Whether the Communication is private or not
     * @type {boolean}
     * @memberof CommunicationRequestCompound
     */
    bCommunicationPrivate:boolean 
    /**
     * How the attachment should be included in the email.   Only used if eCommunicationType is **Email**
     * @type {string}
     * @memberof CommunicationRequestCompound
     */
    eCommunicationAttachmenttype?:CommunicationRequestCompoundECommunicationAttachmenttypeEnum 
    /**
     * The number of days before the attachment link expired.   Only used if eCommunicationType is **Email** and eCommunicationattachmentType is **Link**
     * @type {number}
     * @memberof CommunicationRequestCompound
     */
    iCommunicationAttachmentlinkexpiration?:number 
    /**
     * Whether we ask for a read receipt or not.
     * @type {boolean}
     * @memberof CommunicationRequestCompound
     */
    bCommunicationReadreceipt?:boolean 
    /**
     * 
     * @type {Array<CustomCommunicationattachmentRequest>}
     * @memberof CommunicationRequestCompound
     */
    a_objCommunicationattachment:Array<CustomCommunicationattachmentRequest> 
    /**
     * 
     * @type {Array<CommunicationrecipientRequestCompound>}
     * @memberof CommunicationRequestCompound
     */
    a_objCommunicationrecipient:Array<CommunicationrecipientRequestCompound> 
    /**
     * 
     * @type {Array<CommunicationreferenceRequestCompound>}
     * @memberof CommunicationRequestCompound
     */
    a_objCommunicationreference:Array<CommunicationreferenceRequestCompound> 
    /**
     * 
     * @type {Array<CommunicationexternalrecipientRequestCompound>}
     * @memberof CommunicationRequestCompound
     */
    a_objCommunicationexternalrecipient:Array<CommunicationexternalrecipientRequestCompound> 
}


export const CommunicationRequestCompoundECommunicationAttachmenttypeEnum = {
    Attachment: 'Attachment',
    Url: 'Url'
} as const;
export type CommunicationRequestCompoundECommunicationAttachmenttypeEnum = typeof CommunicationRequestCompoundECommunicationAttachmenttypeEnum[keyof typeof CommunicationRequestCompoundECommunicationAttachmenttypeEnum];


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomCommunicationsenderRequest } from './'
// @ts-ignore
import { ValidationObjectCustomCommunicationsenderRequest } from './'

/**
 * @export 
 * A CommunicationRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationRequestCompound
 */
export class DataObjectCommunicationRequestCompound {
    pkiCommunicationID?:number = undefined
    eCommunicationImportance?:FieldECommunicationImportance = undefined
    eCommunicationType:FieldECommunicationType = 'Email'
    objCommunicationsender?:CustomCommunicationsenderRequest = undefined
    sCommunicationSubject?:string = undefined
    tCommunicationBody:string = ''
    bCommunicationPrivate:boolean = false
    eCommunicationAttachmenttype?:CommunicationRequestCompoundECommunicationAttachmenttypeEnum = undefined
    iCommunicationAttachmentlinkexpiration?:number = undefined
    bCommunicationReadreceipt?:boolean = undefined
    a_objCommunicationattachment:Array<CustomCommunicationattachmentRequest> = []
    a_objCommunicationrecipient:Array<CommunicationrecipientRequestCompound> = []
    a_objCommunicationreference:Array<CommunicationreferenceRequestCompound> = []
    a_objCommunicationexternalrecipient:Array<CommunicationexternalrecipientRequestCompound> = []
}

/**
 * @export 
 * A CommunicationRequestCompound Validation Object
 * @class ValidationObjectCommunicationRequestCompound
 */
export class ValidationObjectCommunicationRequestCompound {
   pkiCommunicationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eCommunicationImportance = {
      type: 'enum',
      allowableValues: ['High','Normal','Low'],
      required: false
   }
   eCommunicationType = {
      type: 'enum',
      allowableValues: ['Email','Fax','Sms'],
      required: true
   }
   objCommunicationsender = new ValidationObjectCustomCommunicationsenderRequest()
   sCommunicationSubject = {
      type: 'string',
      pattern: /^.{0,200}$/,
      required: false
   }
   tCommunicationBody = {
      type: 'string',
      required: true
   }
   bCommunicationPrivate = {
      type: 'boolean',
      required: true
   }
   eCommunicationAttachmenttype = {
      type: 'string',
      required: false
   }
   iCommunicationAttachmentlinkexpiration = {
      type: 'integer',
      minimum: 1,
      maximum: 30,
      required: false
   }
   bCommunicationReadreceipt = {
      type: 'boolean',
      required: false
   }
   a_objCommunicationattachment = {
      type: 'array',
      minItems: 0,
      required: true
   }
   a_objCommunicationrecipient = {
      type: 'array',
      minItems: 0,
      required: true
   }
   a_objCommunicationreference = {
      type: 'array',
      minItems: 0,
      required: true
   }
   a_objCommunicationexternalrecipient = {
      type: 'array',
      minItems: 0,
      required: true
   }
} 


