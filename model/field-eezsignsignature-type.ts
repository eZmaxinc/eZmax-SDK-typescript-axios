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
 * The type of signature.  1. **Acknowledgement** is for an acknowledgment of receipt. 2. **City** is to request the city where the document is signed. 3. **Handwritten** is for a handwritten kind of signature where users needs to \"draw\" their signature on screen. 4. **Initials** is a simple \"click to add initials\" block. 5. **Name** is a simple \"Click to sign\" block. This is the most common block of signature. 6. **NameReason** is to ask for a signing reason.  7. **Attachments** is to ask for files as attachment that may be validate in another step.  8. **FieldText** is to ask for a short text. 9. **Fieldtextarea** is to ask for a text
 * @export
 * @enum {string}
 */

export const FieldEEzsignsignatureType = {
    Acknowledgement: 'Acknowledgement',
    City: 'City',
    Handwritten: 'Handwritten',
    Initials: 'Initials',
    Name: 'Name',
    NameReason: 'NameReason',
    Attachments: 'Attachments',
    AttachmentsConfirmation: 'AttachmentsConfirmation',
    FieldText: 'FieldText',
    FieldTextarea: 'FieldTextarea'
} as const;

export type FieldEEzsignsignatureType = typeof FieldEEzsignsignatureType[keyof typeof FieldEEzsignsignatureType];



