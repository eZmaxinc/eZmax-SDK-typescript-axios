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



/**
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/batchDownload
 * @export
 * @interface EzsignfolderBatchDownloadV1Request
 */
export interface EzsignfolderBatchDownloadV1Request {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfolderBatchDownloadV1Request
     */
    /*'a_pkiEzsigndocumentID': Array<number>;*/
    'a_pkiEzsigndocumentID': Array<number>;
    /**
     * The type of document to retrieve.  1. **Signed** Is the final document once all signatures were applied. 2. **Proofdocument** Is the evidence report. 3. **Proof** Is the complete evidence archive including all of the above and more.
     * @type {Array<string>}
     * @memberof EzsignfolderBatchDownloadV1Request
     */
    /*'a_eDocumentType': Array<EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum>;*/
    'a_eDocumentType': Array<EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum>;
}

export const EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum = {
    Signed: 'Signed',
    Proof: 'Proof',
    Proofdocument: 'Proofdocument'
} as const;
export type EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum = typeof EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum[keyof typeof EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderBatchDownloadV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderBatchDownloadV1Request
 */
export class DataObjectEzsignfolderBatchDownloadV1Request {
   a_pkiEzsigndocumentID:Array<number> = []
   a_eDocumentType:Array<EzsignfolderBatchDownloadV1RequestAEDocumentTypeEnum> = ['Signed']
}

/**
 * @export 
 * A EzsignfolderBatchDownloadV1Request Validation Object
 * @class ValidationObjectEzsignfolderBatchDownloadV1Request
 */
export class ValidationObjectEzsignfolderBatchDownloadV1Request {
   a_pkiEzsigndocumentID = {
      type: 'array',
      minItems: 1,
      required: true
   }
   a_eDocumentType = {
      type: 'array',
      required: true
   }
} 


