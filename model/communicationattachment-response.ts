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



import { DefaultObject } from '../base'

/**
 * A Communicationattachment Object
 * @export
 * @interface CommunicationattachmentResponse
 */
export interface CommunicationattachmentResponse {
    /**
     * The unique ID of the Communicationattachment
     * @type {number}
     * @memberof CommunicationattachmentResponse
     */
    'pkiCommunicationattachmentID': number;
    /**
     * The unique ID of the Attachment.
     * @type {number}
     * @memberof CommunicationattachmentResponse
     */
    'fkiAttachmentID'?: number;
    /**
     * The unique ID of the Invoice.
     * @type {number}
     * @memberof CommunicationattachmentResponse
     */
    'fkiInvoiceID'?: number;
    /**
     * The unique ID of the Salarypreparation.
     * @type {number}
     * @memberof CommunicationattachmentResponse
     */
    'fkiSalarypreparationID'?: number;
    /**
     * The name of the Communicationattachment
     * @type {string}
     * @memberof CommunicationattachmentResponse
     */
    'sCommunicationattachmentName': string;
}
/**
 * A CommunicationattachmentResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationattachmentResponse
 */
export class DefaultObjectCommunicationattachmentResponse extends DefaultObject {
   pkiCommunicationattachmentID:number = 0
   fkiAttachmentID?:number = undefined
   fkiInvoiceID?:number = undefined
   fkiSalarypreparationID?:number = undefined
   sCommunicationattachmentName:string = ''
}


