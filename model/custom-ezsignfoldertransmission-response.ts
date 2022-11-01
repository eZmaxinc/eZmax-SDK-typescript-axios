/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignfoldertransmissionSignerResponse } from './custom-ezsignfoldertransmission-signer-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderStep } from './field-eezsignfolder-step';

import { DefaultObject } from '../base'

/**
 * An Ezsignfolder Object in the context of an Ezsignbulksendtransmission
 * @export
 * @interface CustomEzsignfoldertransmissionResponse
 */
export interface CustomEzsignfoldertransmissionResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'pkiEzsignfolderID': number;
    /**
     * 
     * @type {FieldEEzsignfolderStep}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'eEzsignfolderStep': FieldEEzsignfolderStep;
    /**
     * The number of total signatures that were requested in the Ezsignfolder
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'iEzsignfolderSignaturetotal': number;
    /**
     * The number of signatures that were signed in the Ezsignfolder.
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'iEzsignfolderSignaturesigned': number;
    /**
     * 
     * @type {Array<CustomEzsignfoldertransmissionSignerResponse>}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'a_objEzsignfoldertransmissionSigner': Array<CustomEzsignfoldertransmissionSignerResponse>;
}
/**
 * A CustomEzsignfoldertransmissionResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomEzsignfoldertransmissionResponse
 */
export class DefaultObjectCustomEzsignfoldertransmissionResponse extends DefaultObject {
   pkiEzsignfolderID:number = 0
   eEzsignfolderStep:FieldEEzsignfolderStep = 'Unsent'
   iEzsignfolderSignaturetotal:number = 0
   iEzsignfolderSignaturesigned:number = 0
   a_objEzsignfoldertransmissionSigner:Array<CustomEzsignfoldertransmissionSignerResponse> = []
}


