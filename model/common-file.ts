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



/**
 * Object representing a file used in a request or response context 
 * @export
 * @interface CommonFile
 */
export interface CommonFile {
    /**
     * The name of the file
     * @type {string}
     * @memberof CommonFile
     */
    /*'sFileName': string;*/
    'sFileName': string;
    /**
     * The URL used to reach the File
     * @type {string}
     * @memberof CommonFile
     */
    /*'sFileUrl'?: string;*/
    'sFileUrl'?: string;
    /**
     * The Base64 encoded binary content of the File
     * @type {string}
     * @memberof CommonFile
     */
    /*'sFileBase64'?: string;*/
    'sFileBase64'?: string;
    /**
     * The source of the File
     * @type {string}
     * @memberof CommonFile
     */
    /*'eFileSource': CommonFileEFileSourceEnum;*/
    'eFileSource': CommonFileEFileSourceEnum;
}

export const CommonFileEFileSourceEnum = {
    Base64: 'Base64',
    Url: 'Url'
} as const;
export type CommonFileEFileSourceEnum = typeof CommonFileEFileSourceEnum[keyof typeof CommonFileEFileSourceEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonFile Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonFile
 */
export class DataObjectCommonFile {
   sFileName:string = ''
   sFileUrl?:string = undefined
   sFileBase64?:string = undefined
   eFileSource:CommonFileEFileSourceEnum = 'Base64'
}

/**
 * @export 
 * A CommonFile Validation Object
 * @class ValidationObjectCommonFile
 */
export class ValidationObjectCommonFile {
   sFileName = {
      type: 'string',
      required: true
   }
   sFileUrl = {
      type: 'string',
      required: false
   }
   sFileBase64 = {
      type: 'string',
      required: false
   }
   eFileSource = {
      type: 'string',
      required: true
   }
} 


